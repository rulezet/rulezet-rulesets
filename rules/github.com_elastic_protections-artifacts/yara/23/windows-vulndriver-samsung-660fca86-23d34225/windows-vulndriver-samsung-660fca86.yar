rule Windows_VulnDriver_Samsung_660fca86 {
    meta:
        author = "Elastic Security"
        id = "660fca86-552f-4701-8e0e-d745ac1aab34"
        fingerprint = "6510dfe2a9bb9f8645ecd5d9aa5617c5466fcfd62952993ad70da509b39527ef"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "1e24c45ce2672ee403db34077c88e8b7d7797d113c6fd161906dce3784da627d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 42 00 49 00 4F 00 53 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SBIOSIO32.pdb"
        $str2 = "IOCTL_IO_WRITE_PORT"
        $str3 = "IOCTL_IO_READ_PORT"
        $str4 = "Samsung (R) BIOS IO driver" wide
        $str5 = "SBIOSIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}