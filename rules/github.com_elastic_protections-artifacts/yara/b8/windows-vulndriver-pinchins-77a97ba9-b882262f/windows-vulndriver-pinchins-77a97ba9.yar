rule Windows_VulnDriver_Pinchins_77a97ba9 {
    meta:
        author = "Elastic Security"
        id = "77a97ba9-c8cc-46ce-94db-41174c663c78"
        fingerprint = "cba5576c8ed7d0abfd854494030ebc9ac4dac7a62f2025fcb464c30b419975ac"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Pinchins Technology Company Limited, Version: <= 1.0.0.1006"
        threat_name = "Windows.VulnDriver.Pinchins"
        reference_sample = "1a74c2bde0c9a76486657ccb9c79ea87c9891a32cdd4aa15c7542f7c9487a539"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 69 6E 63 68 69 6E 73 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 6D 70 61 6E 79 20 4C 69 6D 69 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 57 00 54 00 4B 00 72 00 6C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xed][\x03-\x03])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\xee-\xee][\x03-\x03][\x00-\x00][\x00-\x00])/
        $str1 = "RWTKrl.pdb"
        $str2 = "RansomwareTerminator" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}