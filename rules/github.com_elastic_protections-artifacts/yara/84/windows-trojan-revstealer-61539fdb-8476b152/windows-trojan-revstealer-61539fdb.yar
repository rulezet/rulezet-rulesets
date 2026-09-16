rule Windows_Trojan_RevStealer_61539fdb {
    meta:
        author = "Elastic Security"
        id = "61539fdb-99cc-48ed-94b8-7f6efa7741bc"
        fingerprint = "ce1a4023b95794dc91eb184df87e2ff640f086accd5b7d7bc5ff965b4499a00d"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies SoftManager module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "14b2ac356ed75d10ef40bbaaa48e7dd9fff7de9719c2a43ad123fe843dd4e4e2"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { B9 F0 00 00 00 88 18 48 FF C0 48 83 E9 01 75 F5 48 8D 44 24 48 48 8B CD 88 18 48 FF C0 48 83 E9 01 }
        $b = { 40 88 30 48 FF C0 48 83 ED 01 75 ?? 49 8B CF 48 8B D7 }
    condition:
        any of them
}