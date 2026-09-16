rule Windows_VulnDriver_CorsairLlAccess_77830b89 {
    meta:
        author = "Elastic Security"
        id = "77830b89-8623-4c50-b77a-4e98833b7a3d"
        fingerprint = "639b1580a382daffddc7c75c43da4ac603578f2c3447b5ae2d9c83297f99be8c"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: Corsair LL Access, Version: <= 1.0.18.0"
        threat_name = "Windows.VulnDriver.CorsairLlAccess"
        reference_sample = "d002134df25f374849ea879c7855aacd7355bc526f31d12b61e60b20266cb480"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 72 00 73 00 61 00 69 00 72 00 20 00 4C 00 4C 00 20 00 41 00 63 00 63 00 65 00 73 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x11][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x12-\x12][\x00-\x00])/
        $str1 = "CorsairLLAccess64.pdb"
        $str2 = "Corsair LL Access" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}