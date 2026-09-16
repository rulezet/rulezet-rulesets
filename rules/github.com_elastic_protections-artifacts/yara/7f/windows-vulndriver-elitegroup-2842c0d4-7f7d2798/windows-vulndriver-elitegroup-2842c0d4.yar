rule Windows_VulnDriver_Elitegroup_2842c0d4 {
    meta:
        author = "Elastic Security"
        id = "2842c0d4-f7ab-416a-8b67-f1d226524d65"
        fingerprint = "179eab85327c2cc3445ccf45036ef8b236ff984c746dd3bebcee24becc93dc72"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Elitegroup Computer Systems Co Ltd, Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Elitegroup"
        reference_sample = "08675796b8712e0e4ccbdf7831450b907bb94c2e3e85560d9aba1b24931f0d55"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 6C 69 74 65 67 72 6F 75 70 20 43 6F 6D 70 75 74 65 72 20 53 79 73 74 65 6D 73 20 43 6F 20 4C 74 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 63 00 63 00 65 00 6C 00 4C 00 69 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AccelLid.pdb"
        $str2 = "IOCTL_KEYBOARD_CONTROL_FUNC"
        $str3 = "IOCTL_KEYBOARD_STATUS_FUNC"
        $str4 = "Lid Accelerometer Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}