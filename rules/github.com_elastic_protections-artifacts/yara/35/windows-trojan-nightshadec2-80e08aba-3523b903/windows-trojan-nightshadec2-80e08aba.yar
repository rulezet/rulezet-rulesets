rule Windows_Trojan_NightshadeC2_80e08aba {
    meta:
        author = "Elastic Security"
        id = "80e08aba-0da8-486d-9fe9-49f5f81708b3"
        fingerprint = "c3754b15db703b3f39ed97a32d2a17a522d324f9bc516d3ba40b2b2a8fb1b9e3"
        creation_date = "2025-09-09"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.NightshadeC2"
        reference_sample = "963c012d56c62093d105ab5044517fdcce4ab826f7782b3e377932da1df6896d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "rundll32 \"%ws\" %ws" wide fullword
        $a2 = "keylog.txt" wide fullword
        $a3 = "\"%ws\" --mute-audio --do-not-de-elevate" wide fullword
        $a4 = "rundll32 \"C:\\Windows\\System32\\shell32.dll\" #61" wide fullword
        $a5 = "powershell Start-Sleep -Seconds 3; Remove-Item -Path %ws -Force" wide fullword
    condition:
        4 of them
}