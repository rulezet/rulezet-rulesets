rule Windows_Generic_Threat_27c975fd {
    meta:
        author = "Elastic Security"
        id = "27c975fd-a448-4a11-9dd1-47b242289175"
        fingerprint = "bc82fc2f745c744708269a7d98ba43d4059cf511c278c7b03f791001ba6830e8"
        creation_date = "2024-10-10"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "0108af363959f90919f24220caf426fba50be3d61f3735bb0f2acbbcc1f56e0c"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 83 6D 0C 01 75 1B FF 75 08 ?? ?? ?? ?? ?? ?? 33 C0 50 50 50 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C0 40 5D C2 0C 00 55 8B EC 83 EC 10 ?? ?? ?? ?? ?? 33 C5 89 45 FC 53 8B D9 }
    condition:
        all of them
}