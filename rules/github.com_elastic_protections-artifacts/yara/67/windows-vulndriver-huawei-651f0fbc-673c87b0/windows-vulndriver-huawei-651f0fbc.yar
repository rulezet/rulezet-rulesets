rule Windows_VulnDriver_Huawei_651f0fbc {
    meta:
        author = "Elastic Security"
        id = "651f0fbc-71e1-46b1-9e56-bcc0d63ce7db"
        fingerprint = "53242f2a65b5339b4fbbe2e6d8498c18564026cac27e9f1461a0d8308e4e2382"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Huawei Technologies Co., Ltd., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Huawei"
        reference_sample = "bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 61 77 65 69 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 77 00 4F 00 73 00 32 00 45 00 63 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HwOs2Ecx64.pdb"
        $str2 = "Huawei MateBook" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}