rule Windows_VulnDriver_Avast_77ea1c4e {
    meta:
        author = "Elastic Security"
        id = "77ea1c4e-99d7-4595-b01f-73ae62ccdc14"
        fingerprint = "f63847f5aeb4d1f438138e1c5eee7397a6758e36a621eed9329bfce4bb8af1ba"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies USA, Inc., Version: <= 19.2.4181.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "a2f45d95d54f4e110b577e621fefa0483fa0e3dcca14c500c298fb9209e491c1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 55 53 41 2C 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x12][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0f]|[\x00-\x54][\x10-\x10])|[\x02-\x02][\x00-\x00][\x13-\x13][\x00-\x00][\x00-\x00][\x00-\x00][\x55-\x55][\x10-\x10])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}