rule Windows_VulnDriver_Avast_5cd9e6b9 {
    meta:
        author = "Elastic Security"
        id = "5cd9e6b9-ccdc-416d-a810-8fa0f0cdee67"
        fingerprint = "c7106958c601b56e51d76adc828de3b8c89d432b3e0924823bc379abe9b3f2e3"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVG Technologies USA, LLC, Version: <= 20.10.171.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "2ce81759bfa236913bbbb9b2cbc093140b099486fd002910b18e2c6e31fdc4f1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 47 20 54 65 63 68 6E 6F 6C 6F 67 69 65 73 20 55 53 41 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xaa][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\xab-\xab][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "AVG Internet Security System " wide
        $str3 = "AVG Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}