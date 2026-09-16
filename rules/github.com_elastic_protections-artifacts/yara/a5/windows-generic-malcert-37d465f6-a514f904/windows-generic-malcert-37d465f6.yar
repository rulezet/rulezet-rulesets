rule Windows_Generic_MalCert_37d465f6 {
    meta:
        author = "Elastic Security"
        id = "37d465f6-e3ee-4984-ae4c-02f5f0287723"
        fingerprint = "59ff0f15adffc730d24d107ae1afe047c22376d117b018356b85c21049cf7d3d"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "381e6c630aaf5ca69f01713be8ac29b11869c8e6af28359e6933407854f086ba"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 22 A9 7A E3 EB EA 8C 98 81 6E 1E 5E }
    condition:
        all of them
}