rule Windows_VulnDriver_Huawei_fcf62f24 {
    meta:
        author = "Elastic Security"
        id = "fcf62f24-a284-4ac4-a005-73279c9df8ec"
        fingerprint = "4a05278d1767ea8f5f8cd3f11a9870c30bd3b10ae2219e1617f36fb61f3833a7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co.,Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HwOs2Ecx64.pdb"
        $str2 = "Huawei MateBook" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}