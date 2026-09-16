rule Windows_VulnDriver_WatchDog_bff2fc23 {
    meta:
        author = "Elastic Security"
        id = "bff2fc23-d972-4f00-bc0f-b3970288bc6a"
        fingerprint = "2a5097cd87e47f98877aa546a9d370be0c4c34c1f36d9021427c7615f03dac79"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: WATCHDOGDEVELOPMENT.COM, LLC, Version: <= 0.3.1.0"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "6278bc785113831b2ec3368e2c9c9e89e8aca49085a59d8d38dac651471d6440"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 57 41 54 43 48 44 4F 47 44 45 56 45 4C 4F 50 4D 45 4E 54 2E 43 4F 4D 2C 20 4C 4C 43 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 73 00 64 00 6B 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "wsdk-driver.pdb"
        $str2 = "WatchDog Antivirus Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}