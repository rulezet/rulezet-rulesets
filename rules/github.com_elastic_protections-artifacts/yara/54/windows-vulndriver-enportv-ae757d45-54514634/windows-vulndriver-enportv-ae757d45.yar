rule Windows_VulnDriver_EnPortv_ae757d45 {
    meta:
        author = "Elastic Security"
        id = "ae757d45-29ae-47c2-a38c-6b4f76bcc69f"
        fingerprint = "f447ea5e6e80eb21efd042138e31fab61301be0dbc22c33aeca0652866c84ebc"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Name: EnPortv.sys, Version: <= 1.26.0.0"
        threat_name = "Windows.VulnDriver.EnPortv"
        reference_sample = "f831f0128c23e9b6559773e6d52890b511b1107aa730a4fed671379cb1c7008c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 6E 00 50 00 6F 00 72 00 74 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x19][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x1a-\x1a][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "EnData.pdb"
        $str2 = "EnCase Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}