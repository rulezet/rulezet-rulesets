rule Windows_VulnDriver_Nvidia_347c169b {
    meta:
        author = "Elastic Security"
        id = "347c169b-54a3-41fc-8861-4fa1b5db38f8"
        fingerprint = "14e7e2948f779de4912dfb5e1809569c37ccb74be93c6ced399aafc1a9c0e814"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: nvoclock.sys, Version: <= 6.2.15.1"
        threat_name = "Windows.VulnDriver.Nvidia"
        reference_sample = "16ae28284c09839900b99c0bdf6ce4ffcd7fe666cfd5cfb0d54a3ad9bea9aa9c"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x0e][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x00-\x00][\x00-\x00][\x0f-\x0f][\x00-\x00]|[\x02-\x02][\x00-\x00][\x06-\x06][\x00-\x00][\x01-\x01][\x00-\x00][\x0f-\x0f][\x00-\x00])/
        $str1 = "nvoclock.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2
}