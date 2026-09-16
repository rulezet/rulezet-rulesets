rule Windows_VulnDriver_Insyde_9198f42c {
    meta:
        author = "Elastic Security"
        id = "9198f42c-9373-4e73-a6c6-2124ebe7eb7c"
        fingerprint = "d98f284075d0fd81dc007ed239892f3a906f1542c03a4bfae2309d687e81bb2b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 1.0.0.1"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "e8d2424037f63aa395085c546aeac0cd7a09567a4e304c509e087d1b3ce199da"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4F 00 41 00 54 00 6F 00 6F 00 6C 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "OAToolx64.pdb"
        $str2 = "OATool x64 Driver" wide
        $str3 = "OAToolx64.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}