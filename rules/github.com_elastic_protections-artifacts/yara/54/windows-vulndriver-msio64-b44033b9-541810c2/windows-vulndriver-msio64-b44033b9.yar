rule Windows_VulnDriver_MsIo64_b44033b9 {
    meta:
        author = "Elastic Security"
        id = "b44033b9-3912-4652-b65a-48bbe4046c71"
        fingerprint = "2ffa9dd59563632d6ffc78da5ee63b544534285538ca926096b592a21f30094e"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher, Version: <= 1.2.20.120"
        threat_name = "Windows.VulnDriver.MsIo64"
        reference_sample = "cfcf32f5662791f1f22a77acb6dddfbc970fe6e99506969b3ea67c03f67687ab"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4D 00 73 00 49 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x77][\x00-\x00][\x14-\x14][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x78-\x78][\x00-\x00][\x14-\x14][\x00-\x00])/
        $str1 = "MsIo64.pdb"
        $str2 = "IOCTL_MSIO_UNMAPPHYSADDR"
        $str3 = "IOCTL_MSIO_MAPPHYSTOLIN"
        $str4 = "MsIo64 Driver Version 1.2" wide
        $str5 = "MICSYS IO driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}