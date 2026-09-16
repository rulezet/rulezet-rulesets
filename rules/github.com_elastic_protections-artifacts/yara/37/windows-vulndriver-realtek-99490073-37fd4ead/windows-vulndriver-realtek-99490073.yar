rule Windows_VulnDriver_Realtek_99490073 {
    meta:
        author = "Elastic Security"
        id = "99490073-2f57-4ac2-9e05-c66a17db2a42"
        fingerprint = "4e9121ae638bf627170b1a66ae451ac763fb0ecb7eef37f4f41545794b60265c"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 10.0.22000.12024"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "b19ec8330b026100f705c05b793030ca109e15cbec4ada13b452acf259cc29d5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 74 00 73 00 54 00 70 00 78 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x54]|[\x00-\xef][\x55-\x55])|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x2d]|[\x00-\xf7][\x2e-\x2e])[\xf0-\xf0][\x55-\x55]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\xf8-\xf8][\x2e-\x2e][\xf0-\xf0][\x55-\x55])/
        $str1 = "RtsTpx.pdb"
        $str2 = "RtsTpx driver for Realtek Type-C device" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}