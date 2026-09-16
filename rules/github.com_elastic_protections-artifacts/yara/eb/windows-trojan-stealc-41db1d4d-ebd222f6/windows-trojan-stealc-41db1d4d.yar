rule Windows_Trojan_Stealc_41db1d4d {
    meta:
        author = "Elastic Security"
        id = "41db1d4d-d19f-441b-82c3-5ae94ef2baab"
        fingerprint = "be16274bf7c8fe038b19700aaae47ff0ffcf9cbb98ac93adb7e228c5854b782c"
        creation_date = "2025-07-16"
        last_modified = "2025-09-19"
        threat_name = "Windows.Trojan.Stealc"
        reference_sample = "a68bc167669c7c98b6742209acea111be61e6002aa652a7b8116af47b284b084"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "C:\\builder_v2\\stealc\\json.h" wide fullword
        $a2 = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" fullword
        $a3 = "/c timeout /t 5 & del /f /q \"" fullword
        $b1 = { 0F B7 C8 81 E9 19 04 00 00 74 14 83 E9 09 74 0F 83 E9 01 74 0A 83 E9 1C 74 05 83 F9 04 75 08 33 C9 FF }
        $b2 = { 22 74 6F 74 61 6C 5F 70 61 72 74 73 22 3A 20 00 2C 20 00 00 00 00 00 00 22 70 61 72 74 5F 69 6E 64 65 78 22 3A 20 }
        $b3 = { 48 89 5C 24 10 57 48 83 EC ?? 0F 57 C0 48 8D 3D [3] 00 0F 11 01 48 C7 41 10 00 00 00 00 48 8B D9 48 C7 41 18 0F 00 00 00 C6 01 00 8A 05 [3] 00 EB }
    condition:
        3 of them
}