rule Windows_VulnDriver_Novell_faa58d6d {
    meta:
        author = "Elastic Security"
        id = "faa58d6d-cbf6-4ac8-9637-de96ba70dfc5"
        fingerprint = "8020b3b744f6dc3cfd6fbcda3059341ce7dc80d3660e186efb25d75c7a07950d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Novell, Inc., Version: <= 3.1.12.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "00b3ff11585c2527b9e1c140fd57cb70b18fd0b775ec87e9646603056622a1fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 6F 76 65 6C 6C 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 49 00 43 00 4D 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0c-\x0c][\x00-\x00])/
        $str1 = "ncpl.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell Client Portability Layer" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}