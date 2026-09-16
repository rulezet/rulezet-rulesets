rule Windows_Trojan_Generic_41da339f {
    meta:
        author = "Elastic Security"
        id = "41da339f-0266-4e8e-bae6-9b4c58210856"
        fingerprint = "6c6d63d9595bc37714bf33ccda155825c507f566b1654182a85e86e0e3bffb49"
        creation_date = "2026-01-26"
        last_modified = "2026-02-02"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2340f152e8cb4cc7d5d15f384517d756a098283aef239f8cbfe3d91f8722800a"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $pdb = { 43 3A 5C 55 73 65 72 73 5C 41 64 6D 69 6E 69 73 74 72 61 74 6F 72 5C 44 65 73 6B 74 6F 70 5C E6 9B BF E6 8D A2 E9 85 8D E7 BD AE E6 96 87 E4 BB B6 5C 77 33 77 70 2D 73 76 63 68 6F 73 74 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 43 62 73 4D 73 67 41 70 69 2E 70 64 62 }
        $str1 = "C:\\Windows\\System32\\drivers\\WUDFPfprot.sys" fullword
        $str2 = "C:\\Windows\\System32\\drivers\\WppRecorderpo.sys" fullword
        $str3 = "C:\\Windows\\System32\\drivers\\WppRecorderrt.sys" fullword
        $str4 = "WsmRes64.dll" fullword
        $str5 = "CbsMsgApi.dll" fullword
    condition:
        $pdb or 4 of ($str*)
}