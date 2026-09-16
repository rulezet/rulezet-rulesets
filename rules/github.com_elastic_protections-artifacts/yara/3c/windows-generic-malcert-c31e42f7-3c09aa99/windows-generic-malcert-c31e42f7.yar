rule Windows_Generic_MalCert_c31e42f7 {
    meta:
        author = "Elastic Security"
        id = "c31e42f7-a997-437f-8b64-26328bf97f0b"
        fingerprint = "c4408f5e02ea43d1b4ff93e5a34451757d342f21c69e5f66ba3cebafb6887083"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "17f3f4424afc18df18b9a9b36408e3f214ae91441f71e800f62dec240563dc6f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 84 9E A0 94 5D D2 EA 2D C3 CC 24 86 57 8A 57 15 }
    condition:
        all of them
}