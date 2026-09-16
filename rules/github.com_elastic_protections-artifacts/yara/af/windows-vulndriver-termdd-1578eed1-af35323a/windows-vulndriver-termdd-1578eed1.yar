rule Windows_VulnDriver_Termdd_1578eed1 {
    meta:
        author = "Elastic Security"
        id = "1578eed1-8905-4d19-8289-690ee607243c"
        fingerprint = "1df91ab53f6b41ffbb8c8830e7efa6fc92ac2406c1165edd45148873a4983c4d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Name: termdd.sys, Version: <= 5.1.2276.1"
        threat_name = "Windows.VulnDriver.Termdd"
        reference_sample = "001e3ecc4c3294712b8a80ad21b6ba952acfdd9f8297eb7dda3ac1d932eaa15e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 74 00 65 00 72 00 6D 00 64 00 64 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x07]|[\x00-\xe3][\x08-\x08])|[\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\xe4-\xe4][\x08-\x08]|[\x01-\x01][\x00-\x00][\x05-\x05][\x00-\x00][\x01-\x01][\x00-\x00][\xe4-\xe4][\x08-\x08])/
        $str1 = "termdd.pdb"
        $str2 = "IcaWaitForMultipleObjects"
        $str3 = "IcaBufferGetUsableSpace"
        $str4 = "Microsoft(R) Windows (R) 2000 Operating System" wide
        $str5 = "Terminal Server Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}