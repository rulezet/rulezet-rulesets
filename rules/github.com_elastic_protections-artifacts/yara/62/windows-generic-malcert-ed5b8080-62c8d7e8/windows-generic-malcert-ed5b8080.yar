rule Windows_Generic_MalCert_ed5b8080 {
    meta:
        author = "Elastic Security"
        id = "ed5b8080-f173-47b5-b560-98c82a667754"
        fingerprint = "92f2506c459997e259f7970c931aafd5b52b074349b06286dafdc75e29a484c8"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "db827af8d120c894e82590ad6b4ca1d19e8f41541a7d3ea38734443d88deb6fd"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 4B 6F 02 3B 59 59 7E 8E 95 3D B4 CD 7C 0B 52 5A }
    condition:
        all of them
}