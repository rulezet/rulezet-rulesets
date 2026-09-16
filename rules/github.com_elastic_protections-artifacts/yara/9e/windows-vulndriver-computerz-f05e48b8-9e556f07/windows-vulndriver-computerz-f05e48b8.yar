rule Windows_VulnDriver_ComputerZ_f05e48b8 {
    meta:
        author = "Elastic Security"
        id = "f05e48b8-a731-4e7c-895f-e88741511714"
        fingerprint = "362c5d3ec52a656c1edd5947e471c73cc97c8d9ccd8505bfd7994502631fda26"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ComputerZ.Sys, Version: <= 1.0.8.818"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "61f3b1c026d203ce94fab514e3d15090222c0eedc2a768cc2d073ec658671874"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x31][\x03-\x03])[\x08-\x08][\x00-\x00]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x32-\x32][\x03-\x03][\x08-\x08][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "ComputerZ System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}