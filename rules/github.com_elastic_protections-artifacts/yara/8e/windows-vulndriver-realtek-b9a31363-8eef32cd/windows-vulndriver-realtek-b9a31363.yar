rule Windows_VulnDriver_Realtek_b9a31363 {
    meta:
        author = "Elastic Security"
        id = "b9a31363-14ec-40d7-a4f1-541005eff078"
        fingerprint = "7675f9a2f57fe7f9ef18be5d88a6b1cd049ee827430fb5f23847f39b5fd5ec3c"
        creation_date = "2026-05-22"
        last_modified = "2026-08-11"
        description = "Subject: Realtek Semiconductor Corp, Version: <= 1.4.105.2016"
        threat_name = "Windows.VulnDriver.Realtek"
        reference_sample = "db711ec3f4c96b60e4ed674d60c20ff7212d80e34b7aa171ad626eaa8399e8c7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 52 65 61 6C 74 65 6B 20 53 65 6D 69 63 6F 6E 64 75 63 74 6F 72 20 43 6F 72 70 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 72 00 74 00 6B 00 69 00 6F 00 36 00 34 00 2E 00 73 00 79 00 73 00 20 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x68][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xdf][\x07-\x07])[\x69-\x69][\x00-\x00]|[\x04-\x04][\x00-\x00][\x01-\x01][\x00-\x00][\xe0-\xe0][\x07-\x07][\x69-\x69][\x00-\x00])/
        $str1 = "rtkio64.pdb"
        $str2 = "Realtek IO Driver  " wide
        $str3 = "Realtek IO Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}