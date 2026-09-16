rule Windows_VulnDriver_NSecKrnl_182639a6 {
    meta:
        author = "Elastic Security"
        id = "182639a6-5389-4567-8681-91cb63311298"
        fingerprint = "116873acd84f61a9fec024a205e1f1f6a1052d4d0d9b5e285fac0284c3b95063"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 3.7.100.20515"
        threat_name = "Windows.VulnDriver.NSecKrnl"
        reference_sample = "053b5bc1d35c76f2e9574f8403c2f5ce07b9a44d00495ce546662d4c0476fd2d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4E 00 53 00 65 00 63 00 4B 00 72 00 6E 00 6C 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x06][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x4f]|[\x00-\x22][\x50-\x50])[\x64-\x64][\x00-\x00]|[\x07-\x07][\x00-\x00][\x03-\x03][\x00-\x00][\x23-\x23][\x50-\x50][\x64-\x64][\x00-\x00])/
        $str1 = "nskrnl-x86.pdb"
        $str2 = "NSecKrnl" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}