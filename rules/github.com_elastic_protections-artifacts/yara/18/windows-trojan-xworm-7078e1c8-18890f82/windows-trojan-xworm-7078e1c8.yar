rule Windows_Trojan_XWorm_7078e1c8 {
    meta:
        author = "Elastic Security"
        id = "7078e1c8-2f18-4116-8c55-e47b8e948ed7"
        fingerprint = "23304deeddcf211b7b9abc1446d8975a3ef4713e60d0363a1e1d6d69a9e5b514"
        creation_date = "2024-10-10"
        last_modified = "2024-10-24"
        threat_name = "Windows.Trojan.XWorm"
        reference_sample = "034c8a18c15521069af36595357d9c8413a33544af8d3ea5f0ac7d471841e0ec"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 28 00 00 0A 72 5D 01 00 70 17 6F 29 00 00 0A 7E 21 00 00 04 28 2A 00 00 0A 09 6F 2B 00 00 0A 09 28 2C 00 00 0A 2C 0F 09 73 2D 00 00 0A 13 04 11 04 6F 2E 00 00 0A 20 E8 03 00 00 28 1F 00 00 0A }
    condition:
        all of them
}