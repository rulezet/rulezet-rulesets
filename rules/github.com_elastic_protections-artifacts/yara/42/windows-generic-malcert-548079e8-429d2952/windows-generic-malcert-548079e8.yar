rule Windows_Generic_MalCert_548079e8 {
    meta:
        author = "Elastic Security"
        id = "548079e8-2f91-42f4-8aed-edfc2110ce75"
        fingerprint = "7aade63c4d26f4833d3bb5fd0ce524dae4606caf20ed379f55d61669c32f004b"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "83679dfd6331a0a0d829c0f3aed5112b69a7024ff1ceebf7179ba5c2b4d21fc5"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 30 13 85 AA 36 FA E6 35 E7 4B B8 8E }
    condition:
        all of them
}