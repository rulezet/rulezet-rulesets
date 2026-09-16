rule Windows_VulnDriver_Wsftprm_b0957e89 {
    meta:
        author = "Elastic Security"
        id = "b0957e89-3b82-4676-ad65-573fcb3d6643"
        fingerprint = "0608b15e9bc5a92c45fa30afb0c3a403e9265eb63ed5e8883ca902c2ca9decf5"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TPZ SOLUCOES DIGITAIS LTDA, Version: <= 4.0.1.0"
        threat_name = "Windows.VulnDriver.Wsftprm"
        reference_sample = "006e089d3e53a5d3cd55ea7dd7b629e4aae3fbd96ee236b88306ab78236c36ee"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 50 5A 20 53 4F 4C 55 43 4F 45 53 20 44 49 47 49 54 41 49 53 20 4C 54 44 41 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 73 00 66 00 74 00 70 00 72 00 6D 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "wsddprm.pdb"
        $str2 = "Topaz OFD - PM" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}