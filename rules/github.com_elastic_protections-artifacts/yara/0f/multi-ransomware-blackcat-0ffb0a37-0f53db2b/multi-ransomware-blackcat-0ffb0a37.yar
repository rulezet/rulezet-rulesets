rule Multi_Ransomware_BlackCat_0ffb0a37 {
    meta:
        author = "Elastic Security"
        id = "0ffb0a37-e4c3-45be-bd4d-7033e88635aa"
        fingerprint = "319b956ddd57bea22cbee7e521649969c5b1f42ee4af49ad6f25847fb8ee9559"
        creation_date = "2023-07-29"
        last_modified = "2024-06-12"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "57136b118a0d6d3c71e522ea53e3305dae58b51f06c29cd01c0c28fa0fa34287"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = { C8 C8 00 00 00 89 20 00 00 45 01 00 00 32 22 08 0A 20 64 85 }
        $a2 = { 67 69 74 68 75 62 2E 63 6F 6D 2D 31 65 63 63 36 32 39 39 64 62 39 65 63 38 32 33 2F 73 69 6D 70 6C 65 6C 6F 67 2D }
    condition:
        all of them
}