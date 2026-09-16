rule Windows_VulnDriver_Samsung_2cfc2565 {
    meta:
        author = "Elastic Security"
        id = "2cfc2565-07d6-460f-a5ea-e5d53bf9b424"
        fingerprint = "389bbc6e292183a409ce78fd5ff1cb6b711c49360ec422de073a6c0561e6953c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "39336e2ce105901ab65021d6fdc3932d3d6aab665fe4bd55aa1aa66eb0de32f0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 42 00 49 00 4F 00 53 00 49 00 4F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SBIOSIO64.pdb"
        $str2 = "IOCTL_IO_WRITE_PORT"
        $str3 = "IOCTL_IO_READ_PORT"
        $str4 = "Samsung (R) BIOS IO driver" wide
        $str5 = "SBIOSIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}