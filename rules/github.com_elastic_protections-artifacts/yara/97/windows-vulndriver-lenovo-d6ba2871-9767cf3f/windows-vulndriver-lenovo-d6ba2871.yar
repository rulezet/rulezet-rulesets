rule Windows_VulnDriver_Lenovo_d6ba2871 {
    meta:
        author = "Elastic Security"
        id = "d6ba2871-c8ab-452f-aa56-d8b9369dbb15"
        fingerprint = "9ab1762be67151bb2ff7f3148a200ca13867d81c4917ffb6665022324cea880f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: LENOVO, Version: <= 2.5.30.11281"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "5ab36c116767eaae53a466fbc2dae7cfd608ed77721f65e83312037fbd57c946"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 45 4E 4F 56 4F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 42 00 6F 00 6F 00 74 00 52 00 65 00 70 00 61 00 69 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x1d][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x2b]|[\x00-\x10][\x2c-\x2c])[\x1e-\x1e][\x00-\x00]|[\x05-\x05][\x00-\x00][\x02-\x02][\x00-\x00][\x11-\x11][\x2c-\x2c][\x1e-\x1e][\x00-\x00])/
        $str1 = "BootRepair.pdb"
        $str2 = "BootRepair" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}