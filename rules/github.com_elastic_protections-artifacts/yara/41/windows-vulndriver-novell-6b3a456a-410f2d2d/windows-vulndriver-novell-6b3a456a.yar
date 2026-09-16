rule Windows_VulnDriver_Novell_6b3a456a {
    meta:
        author = "Elastic Security"
        id = "6b3a456a-adbc-4ba5-a020-6b99ba69e476"
        fingerprint = "9e7483b45ce225cb7332e06f1d333441a0c053ca7bbfa212f29df39e7a852dbc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.12.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "f77fe6b1e0e913ac109335a8fa2ac4961d35cbbd50729936059aba8700690a9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "nscm.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell XTier Session Manager" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}