rule Windows_VulnDriver_Nvidia_27f9d249 {
    meta:
        author = "Elastic Security"
        id = "27f9d249-9a80-41ad-bda8-e1d07607a52d"
        fingerprint = "620e2617b2962861fd37cf436d4f4ca75fdc5f5836e24d7f92e9e9caf2b777a5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 1.8.0.0"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "afdd66562dea51001c3a9de300f91fc3eb965d6848dfce92ccb9b75853e02508"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 66 00 6C 00 61 00 73 00 68 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "NVIDIA Flash Driver" wide
        $str2 = "NVIDIA Flash Driver, Version 1.8.0" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}