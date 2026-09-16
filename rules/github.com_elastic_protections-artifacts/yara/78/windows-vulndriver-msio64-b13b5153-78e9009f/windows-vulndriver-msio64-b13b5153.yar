rule Windows_VulnDriver_MsIo64_b13b5153 {
    meta:
        author = "Elastic Security"
        id = "b13b5153-0b49-4f5b-af40-3a136b15f291"
        fingerprint = "646c7842857150cd30ce0849ed99c836d4284577a6e51d60ff8fdc41988c12e6"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.3.22.609"
        threat_name = "Windows.VulnDriver.MsIo64"
        reference_sample = "0f035948848432bc243704041739e49b528f35c82a5be922d9e3b8a4c44398ff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 73 00 49 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x15][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x01]|[\x00-\x60][\x02-\x02])[\x16-\x16][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x61-\x61][\x02-\x02][\x16-\x16][\x00-\x00])/
        $str1 = "MsIo64.pdb"
        $str2 = "MsIo64 Driver Version 1.3" wide
        $str3 = "MICSYS IO driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}