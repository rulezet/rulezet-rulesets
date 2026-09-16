rule Windows_VulnDriver_ALSysIO_629b44ac {
    meta:
        author = "Elastic Security"
        id = "629b44ac-db95-48f4-8bee-49edf1383180"
        fingerprint = "ed1429820fc4bfb546147c447244c63cc0d659b58b37f62e9aeebfad2bb61c76"
        creation_date = "2026-04-02"
        last_modified = "2026-06-25"
        description = "Subject: ALCPU, Version: <= 2.0.10.0"
        threat_name = "Windows.VulnDriver.ALSysIO"
        reference_sample = "01af9b2e49907308312be623a125a4cd71da9e626a54dfa746336e5d69c0a70a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 4C 43 50 55 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 41 00 4C 00 53 00 79 00 73 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x09][\x00-\x00]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x0a-\x0a][\x00-\x00])/
        $str1 = "ALSysIO64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1
}