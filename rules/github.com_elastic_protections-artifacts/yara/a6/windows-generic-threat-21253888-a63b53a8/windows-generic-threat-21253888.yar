rule Windows_Generic_Threat_21253888 {
    meta:
        author = "Elastic Security"
        id = "21253888-06dd-4e03-bd02-e3dedd322133"
        fingerprint = "5d74ca16c8e4b81c8aba0942496092521dc9d93e82d1922630cb03ea4e988946"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "95e523f4003a10a906ef7c68a258d402e25f235fa9f2b022faff7cae41185b9c"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 24 34 30 33 61 64 63 37 61 2D 39 64 34 64 2D 34 64 37 39 2D 38 63 34 38 2D 36 36 31 61 64 63 66 66 37 33 65 35 }
    condition:
        all of them
}