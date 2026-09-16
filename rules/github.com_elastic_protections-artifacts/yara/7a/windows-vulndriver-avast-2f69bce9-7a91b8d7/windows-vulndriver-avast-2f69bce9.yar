rule Windows_VulnDriver_Avast_2f69bce9 {
    meta:
        author = "Elastic Security"
        id = "2f69bce9-86ca-483e-bf7d-fb143572cd81"
        fingerprint = "033083a27ea0bd7d491a8370196e61b413398f752e2ce2cc0706e40588cd01ed"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Netherlands B.V., Version: <= 18.5.3931.361"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "1dccd1e13da17bd541a66b48d62e914df390818c15f5f599c636d42c05996ace"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 4E 65 74 68 65 72 6C 61 6E 64 73 20 42 2E 56 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 53 00 50 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0e]|[\x00-\x5a][\x0f-\x0f])|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x68][\x01-\x01])[\x5b-\x5b][\x0f-\x0f]|[\x05-\x05][\x00-\x00][\x12-\x12][\x00-\x00][\x69-\x69][\x01-\x01][\x5b-\x5b][\x0f-\x0f])/
        $str1 = "aswSP.pdb"
        $str2 = "IOCTL_ASWSP_START_REQUEST_AND_SET_RESULTS"
        $str3 = "AVG Internet Security System " wide
        $str4 = "AVG self protection module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}