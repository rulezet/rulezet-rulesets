rule Windows_VulnDriver_ComputerZ_b116b7cc {
    meta:
        author = "Elastic Security"
        id = "b116b7cc-c06a-4a19-9e90-d2419534b5e9"
        fingerprint = "66bedbec61c553bf9822354eb0e5a123808e9201926f149c364e1d8586b80e4a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: ComputerZ.Sys, Version: <= 1.6.11.415"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "39134750f909987f6ebb46cf37519bb80707be0ca2017f3735018bac795a3f8d"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\x9e][\x01-\x01])[\x0b-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x9f-\x9f][\x01-\x01][\x0b-\x0b][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}