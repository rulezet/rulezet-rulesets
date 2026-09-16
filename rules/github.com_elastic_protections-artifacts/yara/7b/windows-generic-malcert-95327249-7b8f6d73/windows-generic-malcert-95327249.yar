rule Windows_Generic_MalCert_95327249 {
    meta:
        author = "Elastic Security"
        id = "95327249-cdba-4f30-9d2f-55fc948c0c71"
        fingerprint = "c80085c0edf45b4dbc88d9426d669aa487a4f28ec2f82334217eb7213631c26c"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "e99a5e18f6772adaef7d0f8fb13de41eb2c25f25e292c2ea278a0b473642c7eb"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 72 BC D4 DE 0F 46 24 38 EF 7A 30 6B 0F 98 E6 68 }
    condition:
        all of them
}