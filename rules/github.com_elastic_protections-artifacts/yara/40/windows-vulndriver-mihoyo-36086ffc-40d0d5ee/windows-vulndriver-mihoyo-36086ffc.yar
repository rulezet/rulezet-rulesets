rule Windows_VulnDriver_Mihoyo_36086ffc {
    meta:
        author = "Elastic Security"
        id = "36086ffc-2928-4645-9646-384932e34357"
        fingerprint = "6bc70c1cb0a692957f33a81024d7bb5e84faa79a8fa2722b86c2c9ce5a087fb9"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Sex Shop SRL, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Mihoyo"
        reference_sample = "19dba69b48b085d9487cc23a4135f3ef4849c181965bffc55baed9fa6c205429"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 65 78 20 53 68 6F 70 20 53 52 4C }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $seq1 = { 0F 10 48 D0 0F 11 4A D0 0F 10 40 E0 0F 11 42 E0 0F 10 48 F0 0F 11 4A F0 49 83 E8 01 75 AE 0F 10 00 0F 11 02 48 8B 40 10 48 89 42 10 48 8B 1B 33 D2 48 8B CD FF C7 }
        $seq2 = { 75 0C C7 05 A8 35 00 00 3D 00 00 00 EB A3 83 F8 02 75 0C C7 05 97 35 00 00 3E 00 00 00 EB 92 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $seq1 and $seq2
}