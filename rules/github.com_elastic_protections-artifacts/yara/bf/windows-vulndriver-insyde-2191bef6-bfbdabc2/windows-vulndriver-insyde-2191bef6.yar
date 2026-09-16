rule Windows_VulnDriver_Insyde_2191bef6 {
    meta:
        author = "Elastic Security"
        id = "2191bef6-be5f-4f06-bbb5-096c748ec26e"
        fingerprint = "f8ab2514df3c6e937747ae574a943b3a34d5ea1ffa230679f257d1c98701d08f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 100.0.7.0"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "7164aaff86b3b7c588fc7ae7839cc09c5c8c6ae29d1aff5325adaf5bedd7c9f5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "H2OSDE_Driver.pdb"
        $str2 = "SEG Windows Driver x64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}