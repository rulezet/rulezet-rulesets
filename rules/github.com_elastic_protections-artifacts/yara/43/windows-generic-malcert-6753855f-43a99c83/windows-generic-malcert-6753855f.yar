rule Windows_Generic_MalCert_6753855f {
    meta:
        author = "Elastic Security"
        id = "6753855f-bb08-4c25-a023-6abe63f6f678"
        fingerprint = "9b9bc569ad0c91f8fe94a31074f718919caa4f92e7fe491ab66a18973cdc2a42"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "bdad526c2010c6dfeb413ecd4972d5681104c1cf667fef1b1e4778ca7d96ec35"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 74 26 D2 1D 23 94 D2 EB 72 25 A7 FF C7 EE 36 BE }
    condition:
        all of them
}