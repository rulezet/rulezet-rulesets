rule Windows_VulnDriver_K7RKScan_4515e9a4 {
    meta:
        author = "Elastic Security"
        id = "4515e9a4-6222-4368-934a-32e173de11d3"
        fingerprint = "63f153cd4dbe200ea8b42318d7b820a6bcc53325895f9d66bc1ccbd5f238d9b7"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Binzhoushi Yongyu Feed Co.,LTd., Version: <= 23.0.0.10"
        threat_name = "Windows.VulnDriver.K7RKScan"
        reference_sample = "b5c2a3fbce455507cc6c11475e69b7333c3823c89e5f5e05493eee2214b24071"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 69 6E 7A 68 6F 75 73 68 69 20 59 6F 6E 67 79 75 20 46 65 65 64 20 43 6F 2E 2C 4C 54 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 4B 00 37 00 52 00 4B 00 53 00 63 00 61 00 6E 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x16][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x00-\x09][\x00-\x00][\x00-\x00][\x00-\x00]|[\x00-\x00][\x00-\x00][\x17-\x17][\x00-\x00][\x0a-\x0a][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "K7RKScan.pdb"
        $str2 = "K7RKScan" wide
        $str3 = "K7RKScan Kernel Module" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}