rule Windows_VulnDriver_Asus_db226282 {
    meta:
        author = "Elastic Security"
        id = "db226282-e1d5-4157-8e47-141378a88890"
        fingerprint = "d835114d0bfc01dac370f58200dd93c9ffe4f0c2f6dcb2602ac5fc911f7e116a"
        creation_date = "2026-05-22"
        last_modified = "2026-06-25"
        description = "Subject: ASUSTEK COMPUTER INC., Version: <= 1.9.7.0"
        threat_name = "Windows.VulnDriver.Asus"
        reference_sample = "1fac3fab8ea2137a7e81a26de121187bf72e7d16ffa3e9aec3886e2376d3c718"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 41 53 55 53 54 45 4B 20 43 4F 4D 50 55 54 45 52 20 49 4E 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 45 00 49 00 4F 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x08][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x06][\x00-\x00]|[\x09-\x09][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x07-\x07][\x00-\x00])/
        $str1 = "EIO.pdb"
        $str2 = "ASUS VGA Kernel Mode Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}