rule Windows_VulnDriver_GPUZ_40dcce91 {
    meta:
        author = "Elastic Security"
        id = "40dcce91-9e37-48a3-adcf-247b7e674b00"
        fingerprint = "91d5c941ae3ec91c2e947f94403ab44dc6e2e1c70db4a06a971dd0ecb32aed3a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp LLC, Version: <= 3.0.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "7d39223e7eb902712aeac77c90b9fa00a6e5e56a68d4c542bcc88556a57ba735"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $version and $str1 and $str2
}