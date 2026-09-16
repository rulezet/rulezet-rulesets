rule Windows_VulnDriver_Asus_9bf33615 {
    meta:
        author = "Elastic Security"
        id = "9bf33615-f7e6-4387-a9fd-ae6d8872430d"
        fingerprint = "9a2c193e56b5cb641fde7eb39093189b36035e66acb6fb21638a354f1eb30ea1"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK Computer Inc., Version: <= 2.5.0.1"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "42851a01469ba97cdc38939b10cf9ea13237aa1f6c37b1ac84904c5a12a81fa0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 6F 6D 70 75 74 65 72 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 72 00 69 00 76 00 65 00 72 00 37 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver7.pdb"
        $str2 = "The driver for the ECtool driver-based tools" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}