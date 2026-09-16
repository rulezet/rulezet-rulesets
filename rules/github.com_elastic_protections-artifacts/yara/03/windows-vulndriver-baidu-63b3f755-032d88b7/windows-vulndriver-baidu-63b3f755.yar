rule Windows_VulnDriver_Baidu_63b3f755 {
    meta:
        author = "Elastic Security"
        id = "63b3f755-12bb-4e7f-9046-852cae8f05aa"
        fingerprint = "a970801c70d2a72cf0ae28889c57b164c317c6fb1e0c5af5362e6c1643a7cfae"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: BAF GERMANY PRIVATE LIMITED, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "80ca1beedf8b7a9b49a78cec959f3d75de208d179de64df7d7f66a620819d5b9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 41 46 20 47 45 52 4D 41 4E 59 20 50 52 49 56 41 54 45 20 4C 49 4D 49 54 45 44 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}