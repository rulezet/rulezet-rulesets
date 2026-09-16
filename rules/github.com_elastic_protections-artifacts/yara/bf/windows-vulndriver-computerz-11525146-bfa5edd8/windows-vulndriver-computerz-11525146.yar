rule Windows_VulnDriver_ComputerZ_11525146 {
    meta:
        author = "Elastic Security"
        id = "11525146-28dc-4edf-b1a2-1fee87ef071d"
        fingerprint = "aa3799fcdfbc2be96c919b2b6c79cbca02a3b0b1cebde9b0d507b967b11a01a0"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: Chengdu Qilu Technology Co. Ltd., Version: <= 1.1019.1025.918"
        threat_name = "Windows.VulnDriver.ComputerZ"
        reference_sample = "64dddd5ac53fe2c9de2b317c09034d1bccaf21d6c03ccfde3518e5aa3623dd66"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 43 68 65 6E 67 64 75 20 51 69 6C 75 20 54 65 63 68 6E 6F 6C 6F 67 79 20 43 6F 2E 20 4C 74 64 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 6F 00 6D 00 70 00 75 00 74 00 65 00 72 00 5A 00 2E 00 53 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\xfa][\x03-\x03])[\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x03]|[\x00-\x00][\x04-\x04])|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x95][\x03-\x03])[\x01-\x01][\x04-\x04]|[\xfb-\xfb][\x03-\x03][\x01-\x01][\x00-\x00][\x96-\x96][\x03-\x03][\x01-\x01][\x04-\x04])/
        $str1 = "ComputerZ.pdb"
        $str2 = "Ludashi System Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2
}