rule Windows_VulnDriver_Realtek_792f0893 {
    meta:
        author = "Elastic Security"
        id = "792f0893-89d1-4016-bc84-54b96c3f8aac"
        fingerprint = "993ce77c2f5f99951e0cf1f3479243ea4c89dc5788317a2091df9cea36039d3f"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 5.0.2195.1711"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "3c0a36990f7eef89b2d5f454b6452b6df1304609903f31f475502e4050241dd8"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 70 00 6F 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\x92][\x08-\x08])|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x05]|[\x00-\xae][\x06-\x06])[\x93-\x93][\x08-\x08]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\xaf-\xaf][\x06-\x06][\x93-\x93][\x08-\x08])/
        $str1 = "rtport.pdb"
        $str2 = "Windows (R) 2003 DDK 3790 provider" wide
        $str3 = "Generic Port I/O for Win32" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}