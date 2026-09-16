rule Windows_VulnDriver_Dell_f02fb07f {
    meta:
        author = "Elastic Security"
        id = "f02fb07f-fe9b-44cb-bfd0-e8ab60250e17"
        fingerprint = "11269e3b777e0918e243604714cf774ec5a38be2f2ad0586c87efb0e9c0895d0"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = ""
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "0584520b4b3bdad1d177329bd9952c0589b2a99eb9676cb324d1fce46dad0b9a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str1 = "c:\\work\\bios\\b6k\\dev\\new_drv\\flash2\\drv\\objfre_wnet_AMD64\\amd64\\DBDrvr64.pdb"
        $str2 = "Dell Inc. Flash BIOS upgrade driver, Copyright (c) Dell Inc. - Release Version 2.0"
        $seq1 = { 53 0F 09 E4 80 E6 80 48 8B C1 49 8B D8 EE E4 80 E6 80 E4 80 E6 80 0F 09 E4 80 E6 80 E4 80 E6 80 5B C3 }
        $seq2 = { 48 89 6C 24 58 0F B7 28 48 89 74 24 60 66 85 ED 8B 70 04 4C 89 64 24 40 44 0F B7 60 08 4C 89 6C 24 38 44 8B 68 0C 4C 89 74 24 30 75 1B 85 F6 75 17 44 8B 44 24 20 45 33 F6 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $str1 and $str2 and $seq1 and $seq2
}