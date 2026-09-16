rule Windows_VulnDriver_Avast_0dde1c4e {
    meta:
        author = "Elastic Security"
        id = "0dde1c4e-8b36-4fc9-9c9e-851809f5cba6"
        fingerprint = "1e53d5537655447abb4cf1af5a03a29dfed880dd5c012a6734a1ab8903f73d47"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software s.r.o., Version: <= 18.6.3979.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "d5c4ff35eaa74ccdb80c7197d3d113c9cd38561070f2aa69c0affe8ed84a77c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x8a][\x0f-\x0f])|[\x06-\x06][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\x00][\x00-\x00][\x8b-\x8b][\x0f-\x0f])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}