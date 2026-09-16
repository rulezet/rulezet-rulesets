rule Windows_VulnDriver_EVGA_1a8123b5 {
    meta:
        author = "Elastic Security"
        id = "1a8123b5-6202-4239-a4af-10e72f66a57c"
        fingerprint = "88ad5b7df7e68cee67a7542920a38b81193d66d3d8720ed0d16b91fd45605730"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: EVGA Corp., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.EVGA"
        reference_sample = "33da2ce240b4559cc6e847d56c5fbeaa3d644ec160841920ea0a098dcee28d0e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 45 56 47 41 20 43 6F 72 70 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "Driver.pdb"
        $str2 = "EVGA Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}