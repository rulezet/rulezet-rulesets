rule Windows_VulnDriver_GameDriverX64_955b72f9 {
    meta:
        author = "Elastic Security"
        id = "955b72f9-2e6c-4c9c-baac-070836d82a01"
        fingerprint = "35239fb8bd185d59c63c162c51076510627bf659e760fce7fe7dc048fe3c2f05"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hunan Goldmind Education Equipment Co., Ltd., Version: <= 7.23.4.7"
        threat_name = "Windows.VulnDriver.GameDriverX64"
        reference_sample = "bf881b14745a870b792c263555c0920a6cc82d36dc3ff29c08a968d028b0fc04"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 75 6E 61 6E 20 47 6F 6C 64 6D 69 6E 64 20 45 64 75 63 61 74 69 6F 6E 20 45 71 75 69 70 6D 65 6E 74 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 61 00 6D 00 65 00 44 00 72 00 69 00 76 00 65 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x16][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x06][\x00-\x00][\x04-\x04][\x00-\x00]|[\x17-\x17][\x00-\x00][\x07-\x07][\x00-\x00][\x07-\x07][\x00-\x00][\x04-\x04][\x00-\x00])/
        $str1 = "PwrdDriver.pdb"
        $str2 = "GameDriverX64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}