rule Windows_VulnDriver_Avast_cc54c33c {
    meta:
        author = "Elastic Security"
        id = "cc54c33c-a644-4df8-9a4c-bee0ffef7ccf"
        fingerprint = "f135f5183d0e304ec1ca651422e7cda3fc77c7ab1cfb59c3644d0c92e146c10b"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: Avast Software s.r.o., Version: <= 20.8.137.0"
        threat_name = "Windows.VulnDriver.Avast"
        reference_sample = "17687cba00ec2c9036dd3cb5430aa1f4851e64990dafb4c8f06d88de5283d6ca"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 76 61 73 74 20 53 6F 66 74 77 61 72 65 20 73 2E 72 2E 6F 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 73 00 77 00 41 00 72 00 50 00 6F 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x88][\x00-\x00]|[\x08-\x08][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00][\x89-\x89][\x00-\x00])/
        $str1 = "aswArPot.pdb"
        $str2 = "Avast Antivirus " wide
        $str3 = "Avast Anti Rootkit" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}