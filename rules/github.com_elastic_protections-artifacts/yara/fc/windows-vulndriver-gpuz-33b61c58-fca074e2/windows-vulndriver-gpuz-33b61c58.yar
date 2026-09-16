rule Windows_VulnDriver_GPUZ_33b61c58 {
    meta:
        author = "Elastic Security"
        id = "33b61c58-5036-45a5-81c6-229c84dae212"
        fingerprint = "2af17e05d854189048a469724cfca891437260fae4796d20945f8b23e2c7b78e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp, Version: <= 1.60.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "f9418b5e90a235339a4a1a889490faca39cd117a51ba4446daa1011da06c7ecd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3b][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3c-\x3c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}