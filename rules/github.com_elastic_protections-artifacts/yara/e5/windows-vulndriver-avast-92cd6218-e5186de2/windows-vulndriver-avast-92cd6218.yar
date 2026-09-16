rule Windows_VulnDriver_Avast_92cd6218 {
    meta:
        author = "Elastic Security"
        id = "92cd6218-f78f-45ba-b29b-87ab3678e007"
        fingerprint = "2b98b4f2f9a448d8ecf936f702d59de5a420e12843d788277afd19f14bbac559"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software, Version: <= 8.0.1497.376"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "36505921af5a09175395ebaea29c72b2a69a3a9204384a767a5be8a721f31b10"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 56 00 6D 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x04]|[\x00-\xd8][\x05-\x05])|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x77][\x01-\x01])[\xd9-\xd9][\x05-\x05]|[\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00][\x78-\x78][\x01-\x01][\xd9-\xd9][\x05-\x05])/
        $str1 = "aswVmm.pdb"
        $str2 = "avast! Antivirus" wide
        $str3 = "avast! VM Monitor" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}