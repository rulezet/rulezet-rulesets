rule Windows_VulnDriver_Baidu_33e4d411 {
    meta:
        author = "Elastic Security"
        id = "33e4d411-cec1-4cdc-b413-12a9f3b8188d"
        fingerprint = "e8b4b53520291f41f0c12461a85093c6bfb961ba621f0e106c0f73c6eff7d52e"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: 山西荣升源科贸有限公司, Version: <= 5.0.3.18797"
        threat_name = "Windows.VulnDriver.Baidu"
        reference_sample = "375559359bf5a1d4e132d9e09fc67b3bb55cd07639d49c039267ff22de28b427"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E5 B1 B1 E8 A5 BF E8 8D A3 E5 8D 87 E6 BA 90 E7 A7 91 E8 B4 B8 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x48]|[\x00-\x6c][\x49-\x49])[\x03-\x03][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x6d-\x6d][\x49-\x49][\x03-\x03][\x00-\x00])/
        $str1 = "BdApiUtil64.pdb"
        $str2 = "Baidu Antivirus" wide
        $str3 = "Baidu Antivirus BdApi Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}