rule Windows_VulnDriver_HP_931d8235 {
    meta:
        author = "Elastic Security"
        id = "931d8235-e098-4004-a949-9fb18e8d2708"
        fingerprint = "e1d5bac55a00a5a8f13440805831e20b500459f0e79ea23bb88b5829b894aa61"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 20.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "0d383e469d0e27ebb713770f01f7f1a57068a7d30478221e6f2276125048d1c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 65 00 74 00 64 00 73 00 75 00 70 00 70 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "etdsupp.pdb"
        $str2 = "IOCTL_MG_SUPPORT_DRIVER_VERSION"
        $str3 = "HP ETDi Driver DLL" wide
        $str4 = "ETDi Support Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4
}