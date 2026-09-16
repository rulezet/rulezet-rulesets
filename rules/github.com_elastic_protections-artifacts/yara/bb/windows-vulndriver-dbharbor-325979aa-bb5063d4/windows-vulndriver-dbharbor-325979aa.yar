rule Windows_VulnDriver_DBHarbor_325979aa {
    meta:
        author = "Elastic Security"
        id = "325979aa-1694-4428-b4d1-2942b14a56d7"
        fingerprint = "1a688d59d3038ece102987b715c1fe526f44e57b825aedea4e3394ad5efc5021"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "33a73e36499d4a33f9321c5ac40a4e34c029a2d7ea26205a245592df78195776"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 41 00 45 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorAEx64.pdb"
        $str2 = "SysInfo Auditor" wide
        $str3 = "Driver for SysInfo Detector Pro" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}