rule Windows_VulnDriver_Lenovo_88fa0718 {
    meta:
        author = "Elastic Security"
        id = "88fa0718-88a2-4d32-a9e6-1257d53c9ead"
        fingerprint = "4707590a1d0226ecc81a3fa0ef9c0330112a8c04da96b865346840eef161201a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Lenovo, Version: <= 1.0.35221.0"
        threat_name = "Windows.VulnDriver.Lenovo"
        reference_sample = "9093340be0ab932fa49edd81e9da50914af3e095059908137c49dee991283b81"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4C 65 6E 6F 76 6F }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 52 00 69 00 6E 00 67 00 30 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x88]|[\x00-\x94][\x89-\x89])|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x95-\x95][\x89-\x89])/
        $str1 = "WinRing0.pdb"
        $str2 = "Lenovo Display Control Center" wide
        $str3 = "WinRing0" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}