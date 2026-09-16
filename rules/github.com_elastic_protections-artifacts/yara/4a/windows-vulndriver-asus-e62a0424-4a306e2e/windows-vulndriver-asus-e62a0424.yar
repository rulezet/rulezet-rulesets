rule Windows_VulnDriver_Asus_e62a0424 {
    meta:
        author = "Elastic Security"
        id = "e62a0424-0fb5-4213-936e-a4008fc59b4b"
        fingerprint = "89ec249f0f695aa14bda0eeb2aa231cf9d840be697d54654fd0a91b98f8d6fc7"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 6.32.0.1"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "159e7c5a12157af92e0d14a0d3ea116f91c09e21a9831486e6dc592c93c10980"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 50 00 55 00 20 00 44 00 72 00 69 00 76 00 65 00 72 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x1f][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x20-\x20][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WCPU.pdb"
        $str2 = "Windows (R) Codename Longhorn DDK driver" wide
        $str3 = "ASUS TDE CPU Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}