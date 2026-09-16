rule Windows_Generic_MalCert_326bc791 {
    meta:
        author = "Elastic Security"
        id = "326bc791-5edc-423d-bf42-04d9bffb8cc2"
        fingerprint = "314cd245fce2229fe1ec2fc50fdfd524a44957881eae334fc0762578a6564cd7"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "f8b4164773dfabb8058d869f4ae7a6d2741a885a75fbbcc51722c4ba4e145319"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 01 5A 5B AC 49 42 DB EB AB 59 8A B8 90 D9 2C F5 }
    condition:
        all of them
}