rule Windows_VulnDriver_Intel_7bff0772 {
    meta:
        author = "Elastic Security"
        id = "7bff0772-e9c5-452d-81fc-71dd96064b4e"
        fingerprint = "2ee6bcefd5c4b6a169f575f0b6a2a61d06c48908e52d2af319ebd0ab4cbbb2da"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 9.8.4.59"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "9a91d6e83b8fdec536580f6617f10dfc64eedf14ead29a6a644eb154426622ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 66 00 65 00 43 00 6F 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\x3a][\x00-\x00][\x04-\x04][\x00-\x00]|[\x08-\x08][\x00-\x00][\x09-\x09][\x00-\x00][\x3b-\x3b][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "KfeCo11x64.pdb"
        $str2 = "Killer Traffic Control" wide
        $str3 = "Killer Traffic Control Callout Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}