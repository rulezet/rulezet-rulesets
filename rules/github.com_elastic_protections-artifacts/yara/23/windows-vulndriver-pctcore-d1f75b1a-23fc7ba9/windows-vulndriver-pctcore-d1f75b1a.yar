rule Windows_VulnDriver_PCTCore_d1f75b1a {
    meta:
        author = "Elastic Security"
        id = "d1f75b1a-088b-403e-92fd-4342bf938949"
        fingerprint = "1f938d705226bc6597a95e1c3085768cf86cca22322c2f388dc85cf947584031"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: PCTCore.sys, Version: <= 2.0.0.37"
        threat_name = "Windows.VulnDriver.PCTCore"
        reference_sample = "c85a37ac2984c573c20f7338e819d5a5bd3922f35ca730824fb8fd836c65f3d7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 50 00 43 00 54 00 43 00 6F 00 72 00 65 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x24][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x25-\x25][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "PCTCore64.pdb"
        $str2 = "Kernel Driver Suite" wide
        $str3 = "PC Tools KDS Core Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2 and $str3
}