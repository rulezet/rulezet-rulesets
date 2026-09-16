rule Windows_VulnDriver_Baidu_03175bb0 {
    meta:
        author = "Elastic Security"
        id = "03175bb0-3e14-4fa0-95b5-207418029cd1"
        fingerprint = "19a149595fa952e01c7fa5ebe662d8c8b49fbd09b156a9df5145a8eff89a0f88"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Baidu Online Network Technology (Beijing)Co., Ltd, Version: <= 5.4.3.53276"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "568ad3abf24d40c811ba56d880123641d3796ba79eed4777b28c03fd97a9ee16"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 61 69 64 75 20 4F 6E 6C 69 6E 65 20 4E 65 74 77 6F 72 6B 20 54 65 63 68 6E 6F 6C 6F 67 79 20 28 42 65 69 6A 69 6E 67 29 43 6F 2E 2C 20 4C 74 64 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\xcf]|[\x00-\x1b][\xd0-\xd0])[\x03-\x03][\x00-\x00]|[\x04-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x1c-\x1c][\xd0-\xd0][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}