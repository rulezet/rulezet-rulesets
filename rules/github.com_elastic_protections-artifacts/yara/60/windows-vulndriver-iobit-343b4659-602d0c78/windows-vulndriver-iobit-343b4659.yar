rule Windows_VulnDriver_IObit_343b4659 {
    meta:
        author = "Elastic Security"
        id = "343b4659-26fa-42bd-93dc-685738b291a5"
        fingerprint = "c545b86cf74048a2f0e4c2ab8ae74ac8e3d0c538c1b1210de61d8ef012d710b2"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.2.0.0"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "0209934453e9ce60b1a5e4b85412e6faf29127987505bfb1185fc9296c578b09"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "IObitUnlocker" wide
        $str3 = "IObitUnlocker Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3
}