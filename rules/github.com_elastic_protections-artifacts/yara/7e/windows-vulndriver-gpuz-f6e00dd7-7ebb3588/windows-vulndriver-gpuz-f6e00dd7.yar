rule Windows_VulnDriver_GPUZ_f6e00dd7 {
    meta:
        author = "Elastic Security"
        id = "f6e00dd7-2567-4b51-8171-691dfc4a3385"
        fingerprint = "003fa34df3656d75c760857175b2b805c4162b63486d386c9e0a0d0208ff7b29"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: techPowerUp, Version: <= 1.25.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "7b1529da3469a46d738a20b98e49f78e1b24aed34a62ea5440db78ccda73e972"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 74 65 63 68 50 6F 77 65 72 55 70 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x18][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x19-\x19][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Release64.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}