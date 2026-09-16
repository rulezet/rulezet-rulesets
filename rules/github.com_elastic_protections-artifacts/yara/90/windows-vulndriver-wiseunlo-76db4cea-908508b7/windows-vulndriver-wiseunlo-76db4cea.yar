rule Windows_VulnDriver_WiseUnlo_76db4cea {
    meta:
        author = "Elastic Security"
        id = "76db4cea-d595-41e5-9639-0123532f4fa8"
        fingerprint = "d5f5432aa730401a94d650e7e69a93a464fa0b367042bd65dfbf96a1fd72be0e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing Lang Xingda Network Technology Co., Ltd, Version: <= 1.0.2.13"
        threat_name = "Windows.VulnDriver.WiseUnlo"
        reference_sample = "87aae726bf7104aac8c8f566ea98f2b51a2bfb6097b6fc8aa1f70adeb4681e1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4C 61 6E 67 20 58 69 6E 67 64 61 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 73 00 65 00 55 00 6E 00 6C 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x0c][\x00-\x00][\x02-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x0d-\x0d][\x00-\x00][\x02-\x02][\x00-\x00])/
        $str1 = "WiseUnlock.pdb"
        $str2 = "WiseUnlo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}