rule Windows_VulnDriver_Baidu_225408a6 {
    meta:
        author = "Elastic Security"
        id = "225408a6-3ac0-4db2-9261-e6ecfd46b47f"
        fingerprint = "6ce66da6551161cc0addc21fd3031be53fae7b26521f73d7317b4cea537345a9"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Baidu Online Network Technology (Beijing) Co.,Ltd., Version: <= 5.4.3.59571"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "d2edf53be389c59eff114694576a0c55cdf1b3ef266121ecdae11e711d433032"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 61 69 64 75 20 4F 6E 6C 69 6E 65 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 28 42 65 69 6A 69 6E 67 29 20 43 6F 2E 2C 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xe7]|[\x00-\xb2][\xe8-\xe8])[\x03-\x03][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\xb3-\xb3][\xe8-\xe8][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}