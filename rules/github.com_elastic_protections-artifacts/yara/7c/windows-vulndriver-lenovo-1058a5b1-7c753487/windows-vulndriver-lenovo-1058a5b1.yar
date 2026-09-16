rule Windows_VulnDriver_Lenovo_1058a5b1 {
    meta:
        author = "Elastic Security"
        id = "1058a5b1-ee79-462d-9954-6d10c36e6970"
        fingerprint = "e7135991f41c265ce5d284fafce2a36c51dfcc50ce72b067b7e8e18aa26c2aee"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo Information Products (Shenzhen) Co.,Ltd, Version: <= 6.1.7600.16385"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "05f7419335418b1eb5c983860a8a68e73147508b31e7cb1341a9dbeeb81f96b4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F 20 49 6E 66 6F 72 6D 61 74 69 6F 6E 20 50 72 6F 64 75 63 74 73 20 28 53 68 65 6E 7A 68 65 6E 29 20 43 6F 2E 2C 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4C 00 44 00 69 00 61 00 67 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xaf][\x1d-\x1d])|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x3f]|[\x00-\x00][\x40-\x40])[\xb0-\xb0][\x1d-\x1d]|[\x01-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x40-\x40][\xb0-\xb0][\x1d-\x1d])/
        $str1 = "ldiagio.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}