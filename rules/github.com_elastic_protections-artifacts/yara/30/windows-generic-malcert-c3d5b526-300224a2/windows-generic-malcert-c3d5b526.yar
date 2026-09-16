rule Windows_Generic_MalCert_c3d5b526 {
    meta:
        author = "Elastic Security"
        id = "c3d5b526-0e8e-46b1-904d-286cf92319b3"
        fingerprint = "8ab1bbde25f8cd732576aee2bc4763044b622fbad9c81470fda28eaedcf3cd65"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "06497b526cebbfab81e7e0d55118007d80aa84099d99ee5858c822a616ad48a1"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 04 DE 74 F8 06 A1 C7 F9 A3 26 F5 83 72 F5 65 42 }
    condition:
        all of them
}