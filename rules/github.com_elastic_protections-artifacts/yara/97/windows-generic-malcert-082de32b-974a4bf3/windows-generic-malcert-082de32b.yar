rule Windows_Generic_MalCert_082de32b {
    meta:
        author = "Elastic Security"
        id = "082de32b-7eb7-47af-8fe0-16523ecee53f"
        fingerprint = "4b0e48b4af0d146499c265fc4fab14a02aaedc348e977b88aac2192a70a6d719"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6a75f271addce817d0350ac7ec7eacc15bfb8bf558284382b4f88bad87606faa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 52 74 D0 11 18 FF EB BD D7 E2 73 5A }
    condition:
        all of them
}