rule Windows_VulnDriver_Mitac_471cf3ba {
    meta:
        author = "Elastic Security"
        id = "471cf3ba-a983-442d-ac07-429f3226eeda"
        fingerprint = "0d2c6a070693f73197096571898ce04fee90bb40c4cce5e9833161e445ec0d22"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Mitac Technology Corporation, Version: <= 21.1.1.0"
        threat_name = "Windows.VulnDriver.Mitac"
        reference_sample = "91afa3de4b70ee26a4be68587d58b154c7b32b50b504ff0dc0babc4eb56578f4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 74 61 63 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 56 00 64 00 42 00 53 00 76 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x15-\x15][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x15-\x15][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x15-\x15][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "vddev.pdb"
        $str2 = "IOCTL_DEVICE_PCI_READ_WRITE"
        $str3 = "IOCTL_DEVICE_MSR_READ_WRITE"
        $str4 = "MiTAC System Service Provider" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}