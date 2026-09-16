rule Windows_VulnDriver_ALSysIO_e742ea25 {
    meta:
        author = "Elastic Security"
        id = "e742ea25-aa94-4837-bba6-d853ea846fff"
        fingerprint = "2ceb67ac37f0f5ef86284ad81246cb8b36b9bc969fc783c7253ad5ffb42a913c"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: Artur Liberman, Version: <= 2.0.9.0"
        threat_name = "Windows.VulnDriver.ALSysIO"
        reference_sample = "7f375639a0df7fe51e5518cf87c3f513c55bc117db47d28da8c615642eb18bfa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 72 74 75 72 20 4C 69 62 65 72 6D 61 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4C 00 53 00 79 00 73 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "ALSysIO64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}