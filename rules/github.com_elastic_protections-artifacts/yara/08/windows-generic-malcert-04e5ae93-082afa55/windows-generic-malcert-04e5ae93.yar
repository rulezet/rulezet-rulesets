rule Windows_Generic_MalCert_04e5ae93 {
    meta:
        author = "Elastic Security"
        id = "04e5ae93-eb6e-4d2c-8fdb-b55863432ef5"
        fingerprint = "dc12697fcfea799f10356c0306fa5d7587b7f03b893990be6bb854ddd11554fb"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "1a983e597abdb37653baba58de85bb8e55c6f20aa6bcbd7420b9d14dca586bb7"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 0A 43 AC E6 5F 1C EC 7B 0B 10 8D 80 E6 AB A4 BB }
    condition:
        all of them
}