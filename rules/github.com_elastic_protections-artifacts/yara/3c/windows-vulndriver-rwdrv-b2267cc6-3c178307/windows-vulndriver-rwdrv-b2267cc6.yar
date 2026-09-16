rule Windows_VulnDriver_RwDrv_b2267cc6 {
    meta:
        author = "Elastic Security"
        id = "b2267cc6-d27a-4da7-abdf-acfa328c2f9e"
        fingerprint = "47a99a320c05e961cd10c7e49ba460b5ecce1655ad4b5d64f5cfa9850d55d9d4"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: lab-z.com, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "45ba688a4bded8a7e78a4f5b0dc21004e951ddceb014bb92f51a3301d2fbc56a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 6C 61 62 2D 7A 2E 63 6F 6D }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}