rule Windows_VulnDriver_ShiruiElectronics_ccf646ac {
    meta:
        author = "Elastic Security"
        id = "ccf646ac-ac08-4189-9bda-4c33b4a4f2ab"
        fingerprint = "daa1cfc11315b992957eeacd22d72d9afb29071ab4d87802899ba1cb6fa7b5ea"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Guangzhou Shirui Electronics Co., Ltd"
        threat_name = "Windows.VulnDriver.ShiruiElectronics"
        reference_sample = "42322b59f75f3ee3f66d080433c01fe024ca9ce5cbd3acac8a98394ac2a0d659"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 47 75 61 6E 67 7A 68 6F 75 20 53 68 69 72 75 69 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 6F 2E 2C 20 4C 74 64 }
        $str1 = "WinIo.pdb"
        $str2 = "IOCTL_WINIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_WINIO_MAPPHYSTOLIN"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $str3
}