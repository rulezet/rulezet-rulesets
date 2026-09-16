rule Windows_VulnDriver_Insyde_4c6f78b1 {
    meta:
        author = "Elastic Security"
        id = "4c6f78b1-5640-47f5-a25f-464b7d10766a"
        fingerprint = "f581336f8943452ad98dfc2dbda299cde156dfa21d800b9fd6ccae44bb2a41a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Insyde Software Corp., Version: <= 100.0.7.0"
        threat_name = "Windows.VulnDriver.Insyde"
        reference_sample = "0d30c6c4fa0216d0637b4049142bc275814fd674859373bd4af520ce173a1c75"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 73 79 64 65 20 53 6F 66 74 77 61 72 65 20 43 6F 72 70 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 65 00 67 00 77 00 69 00 6E 00 64 00 72 00 76 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x63][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x00-\x00][\x00-\x00][\x64-\x64][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "segwindrvx64.pdb"
        $str2 = "SEG Windows Driver x64" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}