rule Windows_VulnDriver_Zemana_28dbfa92 {
    meta:
        author = "Elastic Security"
        id = "28dbfa92-0f57-4201-b1fe-c6687b46d7f0"
        fingerprint = "a3b0e05aaa62ed2fb7f11662dfdd1de9f6ef81040f8ee66df44d4e2c591f1e60"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Zemana Ltd., Version: <= 2.1.0.208"
        threat_name = "Windows.VulnDriver.Zemana"
        reference_sample = "c02eabc2e096f00e6e46fb3b5cf0062db5e1b9d92877b701d2ea0bf27cd82cbe"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 5A 65 6D 61 6E 61 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\xcf][\x00-\x00][\x00-\x00][\x00-\x00]|[\x01-\x01][\x00-\x00][\x02-\x02][\x00-\x00][\xd0-\xd0][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "zam64.pdb"
        $str2 = "AntiMalware" wide
        $str3 = "Zemana AntiMalware" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1 and $str2 and $str3
}