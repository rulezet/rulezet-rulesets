rule Windows_Generic_MalCert_5b803f85 {
    meta:
        author = "Elastic Security"
        id = "5b803f85-c9d1-4c97-b627-8221196c9f1a"
        fingerprint = "97e76657f7a70801613df3bf18b6bdad7d105cf6242e9a46bffa84dc13a896de"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "6bddbba9adc1a71c245705ca131c99f4d2739d684b71b2e6e197a724838af964"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 10 45 F7 5E 71 E7 32 09 CA 1E C5 D5 D5 D3 F2 88 81 }
    condition:
        all of them
}