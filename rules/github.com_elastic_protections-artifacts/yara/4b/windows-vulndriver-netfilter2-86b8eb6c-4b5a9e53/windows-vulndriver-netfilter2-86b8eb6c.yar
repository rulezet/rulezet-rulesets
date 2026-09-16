rule Windows_VulnDriver_Netfilter2_86b8eb6c {
    meta:
        author = "Elastic Security"
        id = "86b8eb6c-2278-4379-b44e-91d713f997b4"
        fingerprint = "e6dc3b2937cd7812fac056834c675152299892601287f85e98ea0af51562604c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: 九江宏图无忧科技有限公司, Version: <= 1.4.9.5"
        threat_name = "Windows.VulnDriver.Netfilter2"
        reference_sample = "26d67d479dafe6b33c980bd1eed0b6d749f43d05d001c5dcaaf5fcddb9b899fe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E4 B9 9D E6 B1 9F E5 AE 8F E5 9B BE E6 97 A0 E5 BF A7 E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 65 00 74 00 66 00 69 00 6C 00 74 00 65 00 72 00 32 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x04][\x00-\x00][\x09-\x09][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "netfilter2.pdb"
        $str2 = "WYJSQ TDI Hook Driver (WPP)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}