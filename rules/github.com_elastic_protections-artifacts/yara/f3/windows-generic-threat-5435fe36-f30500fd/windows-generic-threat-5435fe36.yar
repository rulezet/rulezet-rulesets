rule Windows_Generic_Threat_5435fe36 {
    meta:
        author = "Elastic Security"
        id = "5435fe36-e581-4fbd-ba17-33e098c4ac9c"
        fingerprint = "b09215ef544d70233a2176589ec16159cabbb77da7a4232777eefe368fedc493"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "8c0e26af4f9c783844ea457c3eb7bb2bbe1bf3f860ce180bacab00456f3ae7c1"
        severity = 50
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 55 8B EC 83 EC 18 C7 45 F0 00 00 00 00 64 A1 30 00 00 00 89 45 EC C7 45 FC 00 00 00 00 8B 4D EC 8B 51 0C 8B 42 14 89 45 F4 8B 4D F4 89 4D F8 EB 08 8B 55 F8 8B 02 89 45 F8 8B 4D F4 8B 55 F8 3B }
    condition:
        all of them
}