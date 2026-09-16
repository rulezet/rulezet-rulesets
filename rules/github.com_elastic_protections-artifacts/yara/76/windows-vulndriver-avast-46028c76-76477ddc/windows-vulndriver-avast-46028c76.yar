rule Windows_VulnDriver_Avast_46028c76 {
    meta:
        author = "Elastic Security"
        id = "46028c76-cee6-44d7-833d-6935e08970c8"
        fingerprint = "7dda88befffd92f07c2760b3d7ddd762493365d34848d62574ce8d9661588943"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 11.0.0.362"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "5fae7e491b0d919f0b551e15e0942ac7772f2889722684aea32cff369e975879"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x69][\x01-\x01])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00][\x6a-\x6a][\x01-\x01][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x86.pdb"
        $str2 = "Avast NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}