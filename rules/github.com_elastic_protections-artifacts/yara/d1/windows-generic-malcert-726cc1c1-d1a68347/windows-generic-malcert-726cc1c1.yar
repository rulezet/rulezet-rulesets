rule Windows_Generic_MalCert_726cc1c1 {
    meta:
        author = "Elastic Security"
        id = "726cc1c1-a331-48d5-9209-1b2c5bd1dee0"
        fingerprint = "2f8123b6d0373bf2a2b4351476e9c1339479f83b822c52dd38fa28cf5acf0f56"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "77e103eaffea71d35b1d06d64fdbe546261e95d6360b608e1688c4c437f4da5e"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 6E 13 E3 2B CD 62 7A 1D 6C 39 EA 1F 17 46 76 3C }
    condition:
        all of them
}