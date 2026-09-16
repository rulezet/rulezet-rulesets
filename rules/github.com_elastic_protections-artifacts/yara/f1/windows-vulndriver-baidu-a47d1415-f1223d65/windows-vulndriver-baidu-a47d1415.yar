rule Windows_VulnDriver_Baidu_a47d1415 {
    meta:
        author = "Elastic Security"
        id = "a47d1415-cf14-4062-880d-e1f09270dc6e"
        fingerprint = "42538b42d4293ea0f1b04a2ad116bf601cbd139a2dd4ec53d80373a1ae245ff0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Partner Tech(Shanghai)Co.,Ltd, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "bc84e03955d94bcda5bbe00871417c9f0e3200df43040cdf674684084ea0db09"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 50 61 72 74 6E 65 72 20 54 65 63 68 28 53 68 61 6E 67 68 61 69 29 43 6F 2E 2C 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}