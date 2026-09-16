rule Windows_Generic_MalCert_a318116e {
    meta:
        author = "Elastic Security"
        id = "a318116e-9a9a-48a2-9cab-0c846bc84c22"
        fingerprint = "e62a415b9ca15450e2e5c0ef5bce551adc2379bdd8dd663c97c6e17c930aa480"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53d60c9bff836ba832c39fecb2d57fffe594dfd0e9149b40f5c9e473bccbf34f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 70 86 6B 58 66 85 F4 F3 9A 5B 47 17 }
    condition:
        all of them
}