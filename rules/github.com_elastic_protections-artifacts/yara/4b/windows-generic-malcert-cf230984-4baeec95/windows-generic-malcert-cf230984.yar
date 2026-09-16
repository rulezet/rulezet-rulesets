rule Windows_Generic_MalCert_cf230984 {
    meta:
        author = "Elastic Security"
        id = "cf230984-5399-4f53-80e7-3c3164ce1c5d"
        fingerprint = "3b22327aeb3fef773758e2eb64016ab9390d8f14167956c38f29441b12423d04"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "746b1ceebc0116b2c1e6c54bd6824b58d289a6067a3d7a53c82d5527414d0aff"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 0B 59 CB 3A 46 C1 6D 81 E8 00 26 DF }
    condition:
        all of them
}