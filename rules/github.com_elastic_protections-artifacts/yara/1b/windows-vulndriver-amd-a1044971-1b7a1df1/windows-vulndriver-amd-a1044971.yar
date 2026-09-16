rule Windows_VulnDriver_AMD_a1044971 {
    meta:
        author = "Elastic Security"
        id = "a1044971-ad33-41bc-8bef-b9e6a3c5c631"
        fingerprint = "1160e799afb1acfeac59c70d29f7784162f603e965706be0f7041db10ce9b59e"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Advanced Micro Devices Inc., Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.AMD"
        reference_sample = "5df689a62003d26df4aefbaed41ec1205abbf3a2e18e1f1d51b97711e8fcdf00"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 44 00 46 00 57 00 4B 00 52 00 4E 00 4C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "USB-C Power Delivery Firmware Update Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}