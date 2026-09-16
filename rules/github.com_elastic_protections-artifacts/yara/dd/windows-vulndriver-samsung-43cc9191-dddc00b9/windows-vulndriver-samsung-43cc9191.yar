rule Windows_VulnDriver_Samsung_43cc9191 {
    meta:
        author = "Elastic Security"
        id = "43cc9191-b87b-452f-b0d1-0da411bfc218"
        fingerprint = "e360b28a8590fe4c25b4e5e6eb2fdbe09d563f26d2c86bc7a9c4c67edbfae79d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Samsung Electronics CO., LTD., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.Samsung"
        reference_sample = "09e863170e546b5889ad02f1effecf6ec8ea0a99d02878548c0415e460618c88"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 61 6D 73 75 6E 67 20 45 6C 65 63 74 72 6F 6E 69 63 73 20 43 4F 2E 2C 20 4C 54 44 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 53 00 53 00 50 00 4F 00 52 00 54 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "SSPORT.pdb"
        $str2 = "Port Contention Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}