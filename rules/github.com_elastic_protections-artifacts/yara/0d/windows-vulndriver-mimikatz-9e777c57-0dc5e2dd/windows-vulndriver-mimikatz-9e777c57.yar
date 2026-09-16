rule Windows_VulnDriver_Mimikatz_9e777c57 {
    meta:
        author = "Elastic Security"
        id = "9e777c57-d109-4a5a-ace5-75eadc967148"
        fingerprint = "fc5c736543f542604489695d5245374b4d2bbf7ccb643fa8bcf027b727e9b286"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Benjamin Delpy, Version: <= 2.2.0.0"
        threat_name = "Windows.VulnDriver.Mimikatz"
        reference_sample = "083f821d90e607ed93221e71d4742673e74f573d0755a96ad17d1403f65a2254"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6D 00 69 00 6D 00 69 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "mimidrv.pdb"
        $str2 = "mimidrv (mimikatz)" wide
        $str3 = "mimidrv for Windows (mimikatz)" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}