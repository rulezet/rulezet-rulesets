rule Windows_Trojan_Remcos_921ef449 {
    meta:
        author = "Elastic Security"
        id = "921ef449-002a-488c-870c-04e6f6194bc9"
        fingerprint = "4f8bfcec82292fd1dd1d660533adc34d91f630d25ab4640dab231b9cec632d60"
        creation_date = "2025-07-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Remcos"
        reference_sample = "41fc369e2f92f3c5809817271a76d32beb607102aae308b172a7b0389d6eef6e"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "Remcos Agent initialized (" fullword
        $a2 = "Remcos v" fullword
        $a3 = "Uploading file to Controller: " fullword
        $a4 = "alarm.wav" fullword
        $a5 = "[%04i/%02i/%02i %02i:%02i:%02i " wide fullword
        $a6 = "time_%04i%02i%02i_%02i%02i%02i" wide fullword
        $a7 = "[Cleared browsers logins and cookies.]" fullword
        $a8 = "[Chrome StoredLogins found, cleared!]" fullword
    condition:
        4 of them
}