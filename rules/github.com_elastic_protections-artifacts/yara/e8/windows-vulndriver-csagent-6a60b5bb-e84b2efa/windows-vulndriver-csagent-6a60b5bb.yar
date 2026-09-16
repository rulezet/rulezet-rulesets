rule Windows_VulnDriver_CSAgent_6a60b5bb {
    meta:
        author = "Elastic Security"
        id = "6a60b5bb-26a5-417f-bde7-bb3fc81c81b5"
        fingerprint = "41d0d9a664bb888b487fbc3f8abc84ecf5039e4a6c80ca99bf4286a0dba93147"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Shenzhen yundian Technology Co., Ltd, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "b7703a59c39a0d2f7ef6422945aaeaaf061431af0533557246397551b8eed505"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 68 65 6E 7A 68 65 6E 20 79 75 6E 64 69 61 6E 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "pVVIOoBMRFmpaxPTpRhQmuJdkV.pdb"
        $str2 = "CrowdStrike Falcon Sensor" wide
        $str3 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}