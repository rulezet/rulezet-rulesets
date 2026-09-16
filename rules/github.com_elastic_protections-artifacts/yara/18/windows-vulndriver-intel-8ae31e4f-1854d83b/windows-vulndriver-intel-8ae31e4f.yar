rule Windows_VulnDriver_Intel_8ae31e4f {
    meta:
        author = "Elastic Security"
        id = "8ae31e4f-b5ac-4697-bf3d-5216ff34ef62"
        fingerprint = "af635c1cc58ec04f0d1cfec23e6c7d918aac310b1c298ef3405ab047ce270cf8"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Intel Corporation, Version: <= 2.0.0.0"
        threat_name = "Windows.VulnDriver.Intel"
        reference_sample = "37022838c4327e2a5805e8479330d8ff6f8cd3495079905e867811906c98ea20"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 6C 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 73 00 74 00 64 00 63 00 64 00 72 00 76 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "stdcdrv64.pdb"
        $str2 = "SelfTest Data Collector" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}