rule Windows_VulnDriver_Avast_bdbb7f30 {
    meta:
        author = "Elastic Security"
        id = "bdbb7f30-4513-47eb-9622-2bf839d735bf"
        fingerprint = "6b1be2a00b2e3f32df8c8aa70bbd7594ac478ef4fdb45ef9d428814c1e2030ae"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: AVAST Software a.s., Version: <= 10.0.0.1126"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "1072beb3ff6b191b3df1a339e3a8c87a8dc5eae727f2b993ea51b448e837636a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 56 41 53 54 20 53 6F 66 74 77 61 72 65 20 61 2E 73 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 67 00 69 00 6F 00 64 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x65][\x04-\x04])[\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00][\x66-\x66][\x04-\x04][\x00-\x00][\x00-\x00])/
        $str1 = "ngiodriver_x86.pdb"
        $str2 = "avast! NG" wide
        $str3 = "avast! NG setup helper driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}