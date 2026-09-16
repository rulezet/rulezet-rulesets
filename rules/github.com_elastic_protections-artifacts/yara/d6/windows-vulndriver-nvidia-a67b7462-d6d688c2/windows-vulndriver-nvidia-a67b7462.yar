rule Windows_VulnDriver_Nvidia_a67b7462 {
    meta:
        author = "Elastic Security"
        id = "a67b7462-14e8-4ad4-bf3c-52d135e0feba"
        fingerprint = "a47ee83093a1a792128131d0054471cd9866816180b6919627b004327c4d31c9"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.5.6.6"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "f4e500a9ac5991da5bf114fa80e66456a2cde3458a3d41c14e127ac09240c114"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x05][\x00-\x00][\x06-\x06][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00][\x06-\x06][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}