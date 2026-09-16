rule Windows_VulnDriver_RwDrv_a9b9dbaf {
    meta:
        author = "Elastic Security"
        id = "a9b9dbaf-6c4f-48bb-96d5-2aa543ab17af"
        fingerprint = "1e17a9116740bdbe99d89dc8f9119ed4dfe9f613598b3ab07b592fe24f3cb323"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: RwDrv.sys, Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.RwDrv"
        reference_sample = "03d2f865b0f5adfdf7cba84ba2ef68e5f601bea134d42d7ec5302e83fcc9c71d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 52 00 77 00 44 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "AxtuDrv.pdb"
        $str2 = "RW-Everything Read & Write Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}