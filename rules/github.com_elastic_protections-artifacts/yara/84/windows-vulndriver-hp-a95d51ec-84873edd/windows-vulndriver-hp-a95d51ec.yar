rule Windows_VulnDriver_HP_a95d51ec {
    meta:
        author = "Elastic Security"
        id = "a95d51ec-57c7-426b-ae44-ef5339b55dc5"
        fingerprint = "590af546d46cb862eaa85dfe626fa9926948f4c4089bf7346dbdccbf248b11b6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hewlett-Packard Company, Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "c1e11e2012216b54b2aad1be37b469d328f39b09352c66e8c74e6032ec858b96"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 65 77 6C 65 74 74 2D 50 61 63 6B 61 72 64 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 68 00 70 00 36 00 34 00 76 00 69 00 73 00 69 00 6F 00 6E 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hp64vision.pdb"
        $str2 = "HP Vision Hardware Diagnostics" wide
        $str3 = "hpvhd 64bit support driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}