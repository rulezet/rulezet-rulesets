rule Windows_Generic_MalCert_276c83b7 {
    meta:
        author = "Elastic Security"
        id = "276c83b7-60cf-4eb3-8fbd-69169e0479ce"
        fingerprint = "b25ceafeece544b1020c628ba5e5611a29ec7007766dba9aff676fe2394112b6"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "8071c7b74e7ca2769f3746ec8cc007caee65474bb77808b7a84c84f877452605"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 FE F3 86 AC 9C 1D 86 36 CB 37 0C 8C 24 7F 44 FA }
    condition:
        all of them
}