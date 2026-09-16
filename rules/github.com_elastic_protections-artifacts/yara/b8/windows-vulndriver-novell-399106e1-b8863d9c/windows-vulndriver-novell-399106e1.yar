rule Windows_VulnDriver_Novell_399106e1 {
    meta:
        author = "Elastic Security"
        id = "399106e1-3800-4613-b087-b689ae0dd750"
        fingerprint = "0161c037a97f5d09a5331aa403d8714706f14e7e596eb920efd099dfdee0c534"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Publisher, Version: <= 3.1.11.0"
        threat_name = "Windows.VulnDriver.Novell"
        reference_sample = "2e665962c827ce0adbd29fe6bcf09bbb1d7a7022075d162ff9b65d0af9794ac0"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 73 00 63 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x01-\x01][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "nscm.pdb"
        $str2 = "XTCOM_Table"
        $str3 = "Novell XTier" wide
        $str4 = "Novell XTier Session Manager" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}