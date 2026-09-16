rule Windows_VulnDriver_Avast_5af8af76 {
    meta:
        author = "Elastic Security"
        id = "5af8af76-02b7-4f28-a165-84791bb6a967"
        fingerprint = "0a6b6904f34df86faf6bd787b7da24048c493116738234019abe4c874b8b9d34"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Avast Software s.r.o., Version: <= 20.4.83.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "7ad0ab23023bc500c3b46f414a8b363c5f8700861bc4745cecc14dd34bcee9ed"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 76 61 73 74 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x52][\x00-\x00]|[\x04-\x04][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x53-\x53][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}