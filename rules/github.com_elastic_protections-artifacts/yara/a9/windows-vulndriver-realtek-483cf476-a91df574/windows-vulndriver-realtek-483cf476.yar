rule Windows_VulnDriver_Realtek_483cf476 {
    meta:
        author = "Elastic Security"
        id = "483cf476-ff98-448d-ba3b-ae17e955bf64"
        fingerprint = "b38279c6ec1c41f4cc0a55b3bb2677a30ef06fbc2cc7f02ff2eec7e8c6cf54fc"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Name: RTPORT.SYS, Version: <= 1.0.1.0"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "ff322cd0cc30976f9dbdb7a3681529aeab0de7b7f5c5763362b02c15da9657a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 54 00 50 00 4F 00 52 00 54 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "rtport.pdb"
        $str2 = "REALTEK Port I/O" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}