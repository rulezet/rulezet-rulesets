rule Windows_VulnDriver_WatchDog_2e17fccb {
    meta:
        author = "Elastic Security"
        id = "2e17fccb-8be8-4f61-bff5-f5abf5f6e3c3"
        fingerprint = "625b6234e42cebc89da8aa3c26c9f10909d6c7bc0821b5a2eb452f2898eb711e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WATCHDOGDEVELOPMENT.COM, LLC, Version: <= 1.0.600.0"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "12b3d8bc5cc1ea6e2acd741d8a80f56cf2a0a7ebfa0998e3f0743fcf83fabb9e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 41 54 43 48 44 4F 47 44 45 56 45 4C 4F 50 4D 45 4E 54 2E 43 4F 4D 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\x57][\x02-\x02])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x58-\x58][\x02-\x02])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "WatchDog Antimalware Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}