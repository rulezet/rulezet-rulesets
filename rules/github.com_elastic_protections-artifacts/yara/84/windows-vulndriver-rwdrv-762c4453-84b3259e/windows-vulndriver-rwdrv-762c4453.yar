rule Windows_VulnDriver_RwDrv_762c4453 {
    meta:
        author = "Elastic Security"
        id = "762c4453-e733-4453-97dd-f57993cc27c2"
        fingerprint = "a32ce9fdbe60d25d7001e27e982bfd831155c0088927f26305da9ae12b4414a8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: ChongKim Chan, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "ea0b9eecf4ad5ec8c14aec13de7d661e7615018b1a3c65464bf5eca9bbf6ded3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 6F 6E 67 4B 69 6D 20 43 68 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "RwDrv.pdb"
        $str2 = "RwDrv Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}