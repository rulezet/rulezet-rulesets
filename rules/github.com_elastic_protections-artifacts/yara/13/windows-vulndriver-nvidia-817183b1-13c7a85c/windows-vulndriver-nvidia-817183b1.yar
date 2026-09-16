rule Windows_VulnDriver_Nvidia_817183b1 {
    meta:
        author = "Elastic Security"
        id = "817183b1-c0c8-431b-8295-c5f7d71a1a0c"
        fingerprint = "b271cc6dcf41407cdcd591dac6d9bafdeb316e51b593087367a0c1c6b9cae7ed"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: NVIDIA Corporation, Version: <= 6.5.0.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "848b150ffcf1301b26634a41f28deacb5ccdd3117d79b590d515ed49849b8891"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4E 56 49 44 49 41 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "nvflsh64.pdb"
        $str2 = "NVIDIA System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}