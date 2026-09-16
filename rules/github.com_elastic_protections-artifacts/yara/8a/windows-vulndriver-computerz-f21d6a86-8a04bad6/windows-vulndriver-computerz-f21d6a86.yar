rule Windows_VulnDriver_ComputerZ_f21d6a86 {
    meta:
        author = "Elastic Security"
        id = "f21d6a86-ac99-4f87-b721-b453d8014402"
        fingerprint = "556cc2b4ef1884d2d0b946c0b51db15682136416aea5aab2f75815dbcca54b46"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: 360.cn, Version: <= 1.6.12.1018"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "8d3347c93dff62eecdde22ccc6ba3ce8c0446874738488527ea76d0645341409"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 33 36 30 2E 63 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0b][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xf9][\x03-\x03])[\x0c-\x0c][\x00-\x00]|[\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\xfa-\xfa][\x03-\x03][\x0c-\x0c][\x00-\x00])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}