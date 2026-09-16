rule Windows_VulnDriver_Asus_18ff3160 {
    meta:
        author = "Elastic Security"
        id = "18ff3160-6b25-4551-a4fa-0cef1c57edb0"
        fingerprint = "dfb4dd9827d148c54044b171fe4dc94296112e04da0e10607d633a3089b9f4c0"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTeK COMPUTER INC., Version: <= 0.2.1.7"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "e2269e38a00f5328d07af80edb21bb92259b015789f1ab1d7131505a5bc58216"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 65 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 54 00 53 00 5A 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x06][\x00-\x00][\x01-\x01][\x00-\x00]|[\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00][\x01-\x01][\x00-\x00])/
        $str1 = "ATSZIO64.pdb"
        $str2 = "ATSZIO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}