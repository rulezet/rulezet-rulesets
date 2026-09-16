rule Windows_VulnDriver_Intel_44575eec {
    meta:
        author = "Elastic Security"
        id = "44575eec-7fac-4544-8bb8-45b6bd82d6af"
        fingerprint = "afc52152b3c9a51ecb09a1737224c0faeef51d89ace31f44664e277d98d39fb3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: GE Intelligent Platforms Canada Company, Version: <= 9.50.0.7677"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "ae73dd357e5950face9c956570088f334d18464cd49f00c56420e3d6ff47e8dc"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 45 20 49 6E 74 65 6C 6C 69 67 65 6E 74 20 50 6C 61 74 66 6F 72 6D 73 20 43 61 6E 61 64 61 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 47 00 45 00 44 00 65 00 76 00 44 00 72 00 76 00 2E 00 53 00 59 00 53 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x31][\x00-\x00][\x09-\x09][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x32-\x32][\x00-\x00][\x09-\x09][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x1c]|[\x00-\xfc][\x1d-\x1d])[\x00-\x00][\x00-\x00]|[\x32-\x32][\x00-\x00][\x09-\x09][\x00-\x00][\xfd-\xfd][\x1d-\x1d][\x00-\x00][\x00-\x00])/
        $str1 = "GEDevDrv.pdb"
        $str2 = "Proficy Machine Edition" wide
        $str3 = "GE Device Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}