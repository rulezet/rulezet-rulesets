rule Windows_VulnDriver_Dell_2b558646 {
    meta:
        author = "Elastic Security"
        id = "2b558646-45b7-4265-b9d8-3cd0a5df8b81"
        fingerprint = "3e8dcde4aa13a51aa9887b244fbf19e6412df97a87f3b675e7c34d2b3177cfd0"
        creation_date = "2026-07-23"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 2.8.9.4"
        threat_name = "Windows.VulnDriver.Dell"
        reference_sample = "bc2606740e4648c3732541db929f2e02ea8567520d35de57c671e93c71e632f3"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x07][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x08][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x03][\x00-\x00][\x09-\x09][\x00-\x00]|[\x08-\x08][\x00-\x00][\x02-\x02][\x00-\x00][\x04-\x04][\x00-\x00][\x09-\x09][\x00-\x00])/
        $str1 = "DellInstrumentation.pdb"
        $str2 = "DellInstrumentation" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}