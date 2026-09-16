rule Windows_Trojan_RevStealer_0640dc83 {
    meta:
        author = "Elastic Security"
        id = "0640dc83-c415-44ee-8497-c454141a823d"
        fingerprint = "070d18894ff398d117e530087ba0b057c2d1f7b5c15a4eb2b142d61bc1a374c9"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies ProManager module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "13d7237d7289e67c2d806a65d52580b453ce4987acbe2c4c4d04833f55ebccfa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 48 8B 04 24 B9 8B 2F 00 00 0F B7 D0 0F AF D1 0F B7 4C 24 30 0F B7 C2 66 03 C8 66 89 4C 24 38 48 8B 04 24 41 0F B7 04 41 66 89 44 24 28 0F B7 4C 24 28 0F B7 44 24 28 C1 E9 05 66 C1 E0 0B 66 0B C1 }
        $b = { 48 8D 04 11 44 8B 58 1C 8B 58 24 4C 03 D9 8B 78 20 48 03 D9 48 03 F9 8B 48 18 }
    condition:
        any of them
}