rule Windows_VulnDriver_Netfilter2_b5537c11 {
    meta:
        author = "Elastic Security"
        id = "b5537c11-1999-4f8d-a65e-d78b8935b366"
        fingerprint = "68daa35ecc5fbef4b336ef02738e0568ab91062dbab7d1ddf35fcf25aab9e4c1"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 九江宏图无忧科技有限公司, Version: <= 1.5.7.8"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "f1718a005232d1261894b798a60c73d971416359b70d0e545d7e7a40ed742b71"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B9 9D E6 B1 9F E5 AE 8F E5 9B BE E6 97 A0 E5 BF A7 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x07][\x00-\x00][\x07-\x07][\x00-\x00]|[\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x08-\x08][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "WYJSQ WFP Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}