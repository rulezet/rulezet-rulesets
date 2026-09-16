rule Macos_Infostealer_Banshee_08f6de7b {
    meta:
        author = "Elastic Security"
        id = "08f6de7b-88d0-4f3b-9c80-8938d2b874a0"
        fingerprint = "4d9726035e318128db04f0ac05e14abc2c452393eb264a9dd83a2aa697fa2dea"
        creation_date = "2024-08-13"
        last_modified = "2025-08-18"
        threat_name = "Macos.Infostealer.Banshee"
        reference_sample = "11aa6eeca2547fcf807129787bec0d576de1a29b56945c5a8fb16ed8bf68f782"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $str_0 = "No debugging, VM, or Russian language detected." ascii fullword
        $str_1 = "Remote IP: " ascii fullword
        $str_2 = "Russian language detected!" ascii fullword
        $str_3 = " is empty or does not exist, skipping." ascii fullword
        $str_4 = "Data posted successfully" ascii fullword
        $binary_0 = { 8B 55 BC 0F BE 08 31 D1 88 08 48 8B 45 D8 48 83 C0 01 48 89 45 D8 E9 }
        $binary_1 = { 48 83 EC 60 48 89 7D C8 48 89 F8 48 89 45 D0 48 89 7D F8 48 89 75 F0 48 89 55 E8 C6 45 E7 00 }
    condition:
        all of ($str_*) or all of ($binary_*)
}