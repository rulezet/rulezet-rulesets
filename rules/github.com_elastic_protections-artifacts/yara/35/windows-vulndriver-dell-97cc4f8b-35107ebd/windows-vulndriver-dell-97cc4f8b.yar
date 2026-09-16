rule Windows_VulnDriver_Dell_97cc4f8b {
    meta:
        author = "Elastic Security"
        id = "97cc4f8b-06c1-40c3-8a5f-d310715210ad"
        fingerprint = "f472405e1936a71d6aba4fc0664c545b215eb081719bfc50b58dc2a1b008542a"
        creation_date = "2026-07-22"
        last_modified = "2026-08-11"
        description = "Subject: Techporch Incorporated, Version: <= 1.1.0.0"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "51562209e16a1c0247d73d7bfc8827ae4a2e57af11350379a8fba1ec44e56e54"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 70 6F 72 63 68 20 49 6E 63 6F 72 70 6F 72 61 74 65 64 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 44 00 44 00 44 00 72 00 69 00 76 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "dddriver64Dcsa.pdb"
        $str2 = "Dell Diags Device Driver" wide
        $str3 = "DDDriver.sys" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}