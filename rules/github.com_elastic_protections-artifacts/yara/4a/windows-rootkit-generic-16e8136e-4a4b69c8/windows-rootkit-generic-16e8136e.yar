rule Windows_Rootkit_Generic_16e8136e {
    meta:
        author = "Elastic Security"
        id = "16e8136e-482e-49b2-b7b5-a9952b570abe"
        fingerprint = "c1ed4b86934e6658253cdf7c9b6c83dfcfd4ce0ce8e0f8b76889a5b9db6f9222"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 0.0.243.0"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "e9a1c39600193c7fd546733284a575b2d5192e2fd3ff64ca1a33b00739f8d429"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xf2][\x00-\x00]|[\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\xf3-\xf3][\x00-\x00])/
        $str1 = "intigua_driver64.pdb"
        $str2 = "Intigua Release Linux32" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}