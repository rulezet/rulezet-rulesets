rule Windows_Generic_MalCert_ec2b87b1 {
    meta:
        author = "Elastic Security"
        id = "ec2b87b1-15b1-46ae-b38b-17407eb4e7d1"
        fingerprint = "8c48831c856b7da2b821aad3daf4ecf37e87b3ef8231635df038239531cca4bf"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "eef13758a7f78dfda5386aee61d9ab02efd9057963fd4837cac1a866c8f17e1b"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 0C 35 2C 54 2B 8E 0C 2B 4F FE 99 94 E1 }
    condition:
        all of them
}