rule Windows_VulnDriver_Windbg_2912bbcc {
    meta:
        author = "Elastic Security"
        id = "2912bbcc-43ae-4c6e-8567-9f188a314820"
        fingerprint = "0601fd3dd4f7e4ab294bc9aa32ec967bc4ed2710de88402d1b01480a186177a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Binzhoushi Yongyu Feed Co.,LTd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Windbg"
        reference_sample = "f9f2091fccb289bcf6a945f6b38676ec71dedb32f3674262928ccaf840ca131a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6E 7A 68 6F 75 73 68 69 20 59 6F 6E 67 79 75 20 46 65 65 64 20 43 6F 2E 2C 4C 54 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 69 00 6E 00 64 00 62 00 67 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "hpsafe.pdb"
        $str2 = "Microsoft? Windows? Operating System" wide
        $str3 = "Windows GUI symbolic debugger" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}