rule Windows_VulnDriver_AMD_2a24c7eb {
    meta:
        author = "Elastic Security"
        id = "2a24c7eb-060c-4080-93bd-b2cc20b3b1ec"
        fingerprint = "0aa5d7d8e12f5356e9f7e6794ad3dc16bb16f934aad4c331156f737b798067af"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Advanced Micro Devices Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.AMD"
        reference_sample = "0cf84400c09582ee2911a5b1582332c992d1cd29fcf811cb1dc00fcd61757db0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 44 00 46 00 57 00 4B 00 52 00 4E 00 4C 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "USB-C Power Delivery Firmware Update Tool Kernel Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}