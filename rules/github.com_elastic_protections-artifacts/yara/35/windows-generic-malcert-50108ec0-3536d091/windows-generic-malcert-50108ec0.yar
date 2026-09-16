rule Windows_Generic_MalCert_50108ec0 {
    meta:
        author = "Elastic Security"
        id = "50108ec0-956e-4557-a789-80ac894393cd"
        fingerprint = "080c8cc20f5738cab8969b905a3608ec18233f28a55ef4903e11bf7247dfccd0"
        creation_date = "2025-02-05"
        last_modified = "2025-02-10"
        threat_name = "Windows.Generic.MalCert"
        reference_sample = "53091c881ecff5baae1e998a15178d8e9da8f0dcd896d036a82799de5fbe605f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 01 02 02 12 11 21 C4 46 16 E3 C6 35 CF 29 3F 8B E9 DC AB 68 5E 6B }
    condition:
        all of them
}