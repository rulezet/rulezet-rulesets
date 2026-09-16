rule Windows_Trojan_Blister_26f8c5f2 {
    meta:
        author = "Elastic Security"
        id = "26f8c5f2-85db-4fb9-93bc-7d6b28f6f37b"
        fingerprint = "ebed10e211f6743df6592ecfd6a1c6c878f157fca025928f7999d8fecc546e4b"
        creation_date = "2024-09-25"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.Blister"
        reference_sample = "cba30fb1731e165acc256d99d32f3c9e5abfa27d152419d24a91d8b79c5c5cb0"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 41 0F B7 04 40 4D 85 D8 45 3A D4 66 41 89 04 4A 41 84 DE 66 41 39 1C 50 }
        $b = { 41 FF C1 F9 41 0F B7 04 40 4D 85 D8 45 3A D4 66 41 89 04 4A }
    condition:
        any of them
}