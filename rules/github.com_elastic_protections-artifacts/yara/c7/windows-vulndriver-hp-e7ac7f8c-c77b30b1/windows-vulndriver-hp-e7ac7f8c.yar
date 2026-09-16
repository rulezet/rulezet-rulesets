rule Windows_VulnDriver_HP_e7ac7f8c {
    meta:
        author = "Elastic Security"
        id = "e7ac7f8c-eddc-4802-bb08-94855941d9cf"
        fingerprint = "3c66fd618f59e05cd02f0b219725222775a49be831d6d4b69be577db71c8f445"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Hewlett-Packard Company, Version: <= 4.5.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "4024b090cebcabaab884c84ec80ffb15622d12632f236383a9b0a470bff9fe33"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 65 77 6C 65 74 74 2D 50 61 63 6B 61 72 64 20 43 6F 6D 70 61 6E 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 63 00 70 00 71 00 73 00 79 00 73 00 69 00 6F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x03][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x04-\x04][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "cpqsysio64.pdb"
        $str2 = "Physical memory driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}