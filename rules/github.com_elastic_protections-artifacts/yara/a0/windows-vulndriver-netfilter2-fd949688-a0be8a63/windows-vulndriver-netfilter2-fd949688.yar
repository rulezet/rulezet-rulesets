rule Windows_VulnDriver_Netfilter2_fd949688 {
    meta:
        author = "Elastic Security"
        id = "fd949688-593e-4f68-a6c1-bb3be7ee7cf9"
        fingerprint = "4b350f5470a90d8c567da322ae9aa4126e6781efbf0a838a881362c0d3472687"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Shenzhen Hua’nan Xingfa Electronic Equipment Firm, Version: <= 1.6.5.7"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "206006a11f233b9ae876952308f6d60d7a75c80b4d530a3e6146a0b4d8cd3e4f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 48 75 61 E2 80 99 6E 61 6E 20 58 69 6E 67 66 61 20 45 6C 65 63 74 72 6F 6E 69 63 20 45 71 75 69 70 6D 65 6E 74 20 46 69 72 6D }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x06][\x00-\x00][\x05-\x05][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x05-\x05][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "Windows (R) Win 7 DDK driver" wide
        $str3 = "NetFilter SDK WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}