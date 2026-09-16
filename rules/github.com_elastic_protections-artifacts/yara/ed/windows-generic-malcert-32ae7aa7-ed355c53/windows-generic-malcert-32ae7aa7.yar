rule Windows_Generic_MalCert_32ae7aa7 {
    meta:
        author = "Elastic Security"
        id = "32ae7aa7-c196-44de-be7c-69ee823c9bac"
        fingerprint = "e5377c045b7c445defe35fed431bf735671ae9105ee191e3b55b81704cc35742"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "c608a717ff6d907eef8c83512644561d3e18863d42a0f80c778d254d2dcd58aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 11 00 F5 BE 3D 05 57 49 9E 00 6E 00 EF 05 5E 79 19 3E }
    condition:
        all of them
}