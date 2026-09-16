rule Windows_VulnDriver_Zemana_74cfef25 {
    meta:
        author = "Elastic Security"
        id = "74cfef25-393c-4aa9-bfb4-07f881e7559a"
        fingerprint = "288837f7e7fab96e4d33bddaaaab28fdffa8d9455811fa1f2537a30743f66fd0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "c3a2dade7d95085d5af4bf9dc218c97f802440b6c1bd2fdac520cb1a376b7e84"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "IOCTL_CHECK_DRIVER_DISPATCH_ROUTINES"
        $str3 = "IOCTL_FIX_CRITICAL_KERNEL_FUNCTIONS"
        $str4 = "Audit drv" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3 and $str4
}