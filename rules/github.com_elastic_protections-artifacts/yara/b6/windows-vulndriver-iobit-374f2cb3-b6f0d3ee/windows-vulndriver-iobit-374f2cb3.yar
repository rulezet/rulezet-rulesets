rule Windows_VulnDriver_IObit_374f2cb3 {
    meta:
        author = "Elastic Security"
        id = "374f2cb3-4031-4b0f-896b-c2c3a56f8135"
        fingerprint = "b25d4a112a0fd753148ecaa410b9b2f9f7d2c7a956d165bc2661d9054366b5a3"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IObit CO., LTD, Version: <= 1.2.0.2"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "4e1d75684923974c0333d33b789c5d1569ba5a39e8fa6816e825eadaeaf51a2a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 4F 62 69 74 20 43 4F 2E 2C 20 4C 54 44 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "Unlocker" wide
        $str3 = "Unlocker Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}