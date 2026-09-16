rule Windows_VulnDriver_CSAgent_a9947237 {
    meta:
        author = "Elastic Security"
        id = "a9947237-806d-4202-a3db-f845fb38d4a4"
        fingerprint = "b72c0c4cb9c8c82bd03fc7c4a58eeda53b9f24603d1cae2f49b28bdb5e8d2630"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 长沙恒祥信息技术有限公司, Version: <= 6.34.14806.0"
        threat_name = "Windows.VulnDriver.CSAgent"
        reference_sample = "06eccd102c9105957773b32538943531d9c39d0a504ceb3b9b155e97e3b0b134"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E9 95 BF E6 B2 99 E6 81 92 E7 A5 A5 E4 BF A1 E6 81 AF E6 8A 80 E6 9C AF E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 53 00 41 00 67 00 65 00 6E 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x21][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x38]|[\x00-\xd5][\x39-\x39])|[\x22-\x22][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\xd6-\xd6][\x39-\x39])/
        $str1 = "CrowdStrike Falcon Sensor" wide
        $str2 = "CrowdStrike Falcon Sensor Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}