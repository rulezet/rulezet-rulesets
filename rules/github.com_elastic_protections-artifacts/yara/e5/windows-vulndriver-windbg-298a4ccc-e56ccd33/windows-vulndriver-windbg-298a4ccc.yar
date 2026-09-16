rule Windows_VulnDriver_Windbg_298a4ccc {
    meta:
        author = "Elastic Security"
        id = "298a4ccc-b190-4427-b21f-8ea8c4ca33b6"
        fingerprint = "e3748adc0858cecba9071fa9e12c32c11c3a3762b0f349613a31973bcb60d1df"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Wuhan Jiajia Yiyong Technology Co., Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "e6f764c3b5580cd1675cbf184938ad5a201a8c096607857869bd7c3399df0d12"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 75 68 61 6E 20 4A 69 61 6A 69 61 20 59 69 79 6F 6E 67 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 2C 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Microsoft? Windows? Operating System" wide
        $str2 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}