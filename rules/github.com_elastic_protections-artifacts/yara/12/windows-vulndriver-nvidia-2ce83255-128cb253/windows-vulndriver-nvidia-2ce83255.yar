rule Windows_VulnDriver_Nvidia_2ce83255 {
    meta:
        author = "Elastic Security"
        id = "2ce83255-c3a7-4a32-8b36-12285973d1fb"
        fingerprint = "09ade361722fdaabf3e07990a79fc8be000b444e387b07264eb9fde3033a0a62"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Micro-Star Int'l Co., Ltd., Version: <= 5.0.6.6"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "d633055c7eda26dacfc30109eb790625519fc7b0a3a601ceed9e21918aad8a1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 2D 53 74 61 72 20 49 6E 74 27 6C 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}