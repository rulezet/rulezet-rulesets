rule Windows_VulnDriver_AMD_f780a65b {
    meta:
        author = "Elastic Security"
        id = "f780a65b-6c29-472d-8757-d0e3b547ab06"
        fingerprint = "45a2ced25699dfdbc3a5eff44b5659719a47e41d47437bf13caeb4f769a41e79"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Advanced Micro Devices, Inc., Version: <= 4.2.0.0"
        threat_name = "Windows.VulnDriver.AMD"
        reference_sample = "070ff602cccaaef9e2b094e03983fd7f1bf0c0326612eb76593eabbf1bda9103"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 64 76 61 6E 63 65 64 20 4D 69 63 72 6F 20 44 65 76 69 63 65 73 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4F 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AODDriver2.pdb"
        $str2 = "AMD OverDrive Service Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}