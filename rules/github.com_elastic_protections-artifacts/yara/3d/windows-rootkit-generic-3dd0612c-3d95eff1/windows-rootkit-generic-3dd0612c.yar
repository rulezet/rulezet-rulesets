rule Windows_Rootkit_Generic_3dd0612c {
    meta:
        author = "Elastic Security"
        id = "3dd0612c-3ff5-4c49-8afb-a8c4eef340fa"
        fingerprint = "7f803fced1328034faa11c2dd038f8bc1312c1f8d8321a66df2d75fc68655081"
        creation_date = "2026-07-21"
        last_modified = "2026-08-11"
        description = "Subject: Microsoft Windows Hardware Compatibility Publisher"
        threat_name = "Windows.Rootkit.Generic"
        reference_sample = "70c9f9e8dcbba700e0fc20e6ae9b4c5df98326cf212ac8794fc8ee9a46e948c4"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 48 61 72 64 77 61 72 65 20 43 6F 6D 70 61 74 69 62 69 6C 69 74 79 20 50 75 62 6C 69 73 68 65 72 }
        $str1 = "Bro:[%S] Remot:[%s:%d] loP:[%d]->[%d]"
        $str2 = "Add SignSize:%d SignCrc32:%x SignSize2:%d IsSearchFullFile:%d TimeDateStamp:%d"
        $seq1 = { 48 89 5C 24 08 48 89 6C 24 10 57 48 83 EC 20 8B F9 32 DB 48 8D 0D C6 77 00 00 E8 8D 31 00 00 48 8B 05 2A 78 00 00 48 8D 2D 23 78 00 00 }
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2 and $seq1
}