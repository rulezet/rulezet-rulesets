rule Windows_VulnDriver_Netfilter2_713604d3 {
    meta:
        author = "Elastic Security"
        id = "713604d3-aa24-4f77-b48e-c7786d350b16"
        fingerprint = "6934b299af8d77234233f36095dfab2981dda9e682fe7497950def5f56715b8e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.5.9.7"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "81bcd8a3f8c17ac6dc4bad750ad3417914db10aa15485094eef0951a3f72bdbd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x09-\x09][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}