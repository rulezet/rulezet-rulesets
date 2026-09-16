rule Windows_VulnDriver_Avast_447cc9f0 {
    meta:
        author = "Elastic Security"
        id = "447cc9f0-ab72-4ec6-9306-b19ab308b243"
        fingerprint = "4d6685f33763c44f2f34f25aa15094423cc8e379a7d20d7b2e4f70173958d54b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies CZ, s.r.o., Version: <= 17.9.3761.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "7d43769b353d63093228a59eb19bba87ce6b552d7e1a99bf34a54eee641aa0ea"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 43 5A 2C 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x10][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x0d]|[\x00-\xb0][\x0e-\x0e])|[\x09-\x09][\x00-\x00][\x11-\x11][\x00-\x00][\x00-\x00][\x00-\x00][\xb1-\xb1][\x0e-\x0e])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG anti rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}