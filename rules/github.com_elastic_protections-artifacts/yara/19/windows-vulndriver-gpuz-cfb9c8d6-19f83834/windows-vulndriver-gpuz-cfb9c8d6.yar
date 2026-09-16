rule Windows_VulnDriver_GPUZ_cfb9c8d6 {
    meta:
        author = "Elastic Security"
        id = "cfb9c8d6-caf0-4747-98ad-555827dcd0ad"
        fingerprint = "773e5b1a68ac89c803cb0a23e1f6a6bf18f15c6f3b1c773b4ddab9a30993db3a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: TechPowerUp LLC, Version: <= 7.2.0.0"
        threat_name = "Windows.VulnDriver.GPUZ"
        reference_sample = "69fb21e4c8dbfcab838d53d98ec7357d35e30cbbe5fde9e26457d79242ddd78e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 65 63 68 50 6F 77 65 72 55 70 20 4C 4C 43 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x07-\x07][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "driver-x64.pdb"
        $str2 = "Low-Level Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2
}