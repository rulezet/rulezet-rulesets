rule Windows_VulnDriver_CSAgent_08e01875 {
    meta:
        author = "Elastic Security"
        id = "08e01875-19a1-4cdf-a648-63c9c9f6d0bf"
        fingerprint = "5ad28c36c549da1ca4d0dc248656d3c8f7d69dfd603002653e3de40370867362"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: FEI XIAO, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "94b87b1cdaf1d86c2bc4eacef45608d0f16fdd3b981b88cdddc16b6bc64fe25d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 46 45 49 20 58 49 41 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}