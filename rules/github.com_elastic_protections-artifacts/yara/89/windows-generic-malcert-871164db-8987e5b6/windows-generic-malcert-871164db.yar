rule Windows_Generic_MalCert_871164db {
    meta:
        author = "Elastic Security"
        id = "871164db-4ca9-4cad-9ef2-70fc20080aea"
        fingerprint = "ee4b1cc91ca7bcff941f449c6264ef166020aca705f5f59ee35e3aa9b8544ede"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "2ef886a8a67509d25708026b2ea18ce3f6e5a2fecd7b43a900e43dddab9a7935"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0B 35 60 46 7C 36 DE 7E 94 29 E0 A9 78 2D B2 D6 }
    condition:
        all of them
}