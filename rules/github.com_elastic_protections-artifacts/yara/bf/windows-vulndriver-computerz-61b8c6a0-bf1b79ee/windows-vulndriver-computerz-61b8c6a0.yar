rule Windows_VulnDriver_ComputerZ_61b8c6a0 {
    meta:
        author = "Elastic Security"
        id = "61b8c6a0-7d23-4d91-81dc-96055969c2bd"
        fingerprint = "59205fc81068ba22597d8a2035ff4eec410851b35f6e7ac5ddcf52d0af43e62a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: QIHU 360 SOFTWARE CO. LIMITED, Version: <= 1.6.15.1045"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "5c9e257c9740561b5744812e1343815e7972c362c8993d972b96a56e18c712f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 51 49 48 55 20 33 36 30 20 53 4F 46 54 57 41 52 45 20 43 4F 2E 20 4C 49 4D 49 54 45 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x14][\x04-\x04])[\x0f-\x0f][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x15-\x15][\x04-\x04][\x0f-\x0f][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}