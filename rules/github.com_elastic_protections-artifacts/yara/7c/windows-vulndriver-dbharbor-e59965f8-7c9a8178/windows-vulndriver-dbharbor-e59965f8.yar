rule Windows_VulnDriver_DBHarbor_e59965f8 {
    meta:
        author = "Elastic Security"
        id = "e59965f8-2f08-4494-b280-4bc014664988"
        fingerprint = "a17fe043e0e86d575581190a52e51e49ccb51a5dee3bf28212ec1d9981502c1d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Database Harbor Software, Version: <= 2.0.0.3"
        threat_name = "Windows.VulnDriver.DBHarbor"
        reference_sample = "45e5977b8d5baec776eb2e62a84981a8e46f6ce17947c9a76fa1f955dc547271"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 44 61 74 61 62 61 73 65 20 48 61 72 62 6F 72 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 79 00 73 00 49 00 6E 00 66 00 6F 00 44 00 65 00 74 00 65 00 63 00 74 00 6F 00 72 00 58 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SysInfoDetectorX64.pdb"
        $str2 = "SysInfo Detector" wide
        $str3 = "Driver for SysInfo Detector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}