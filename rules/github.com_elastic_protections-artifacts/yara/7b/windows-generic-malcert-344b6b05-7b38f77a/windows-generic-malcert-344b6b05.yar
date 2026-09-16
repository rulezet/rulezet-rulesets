rule Windows_Generic_MalCert_344b6b05 {
    meta:
        author = "Elastic Security"
        id = "344b6b05-6ab1-4a2d-babf-a92fb2dcdefc"
        fingerprint = "41cce85ad5a20851aa5a74d5ed8b983fb28e8967c467a9faee6d517289a909ec"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "4d91a7e24ae7fc3d6e5423c0008707e4e94b0bd3cef153639ba4ec90d61f3c98"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 02 0E B5 27 BA C0 10 99 59 3E 2E A9 02 E3 97 CB }
    condition:
        all of them
}