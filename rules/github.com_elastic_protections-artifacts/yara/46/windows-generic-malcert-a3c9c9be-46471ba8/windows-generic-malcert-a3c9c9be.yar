rule Windows_Generic_MalCert_a3c9c9be {
    meta:
        author = "Elastic Security"
        id = "a3c9c9be-51e3-42e2-b150-bbcb69343f15"
        fingerprint = "59595bf4e3cd8dc3468036485d525ebae590b7944d78cdb710a625b98b290cab"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "d860e6c483cae03f42fc3224db796a33289f48f85dcc8cd58bdc260f9e68f2ad"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 2F 14 7E DC 60 E9 34 24 AF 60 A7 AC }
    condition:
        all of them
}