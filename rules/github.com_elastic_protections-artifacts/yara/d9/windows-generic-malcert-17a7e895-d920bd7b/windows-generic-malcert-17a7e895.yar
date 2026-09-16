rule Windows_Generic_MalCert_17a7e895 {
    meta:
        author = "Elastic Security"
        id = "17a7e895-02fd-41d4-a4c1-617092cecfeb"
        fingerprint = "f16c6eec08a4fa4018a26fd9dd62b12335091e77ae32610becc5f584fab877ef"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "5058a3469d589bdf9279a128db92c792c9aaa6c041aa20f07c4c090ab2152efb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6F EE 7E 57 96 71 E0 C3 36 CC 10 DD 54 1D C6 98 }
    condition:
        all of them
}