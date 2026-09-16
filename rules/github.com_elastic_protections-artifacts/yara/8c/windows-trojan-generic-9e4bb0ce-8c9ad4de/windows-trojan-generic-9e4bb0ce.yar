rule Windows_Trojan_Generic_9e4bb0ce {
    meta:
        author = "Elastic Security"
        id = "9e4bb0ce-b1ed-45dc-8d86-943eb76f0bb4"
        fingerprint = "4fb0eafc58972ef6fef87a88e43ae320420d760f545a66aab28dc3a65f629631"
        creation_date = "2025-10-29"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Generic"
        reference_sample = "2d93a17f04bf2fcd51c2142043af3840895ae7ba43909a26420c4879d214a3c3"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "PluginMe" ascii fullword
        $a2 = "\\cmd.exe -Puppet" ascii fullword
        $a3 = "ERROR 1" ascii fullword
        $a4 = "ERROR 2" ascii fullword
        $a5 = "AYAgent.aye" ascii fullword
        $a6 = "mssecess.exe" ascii fullword
        $a7 = "shell\\open\\command" ascii fullword
        $a8 = "WinSta0\\Default" ascii fullword
        $a9 = { C6 44 24 ?? 53 C6 44 24 ?? 74 C6 44 24 ?? 61 C6 44 24 ?? 30 C6 44 24 ?? 5C }
        $a10 = { C6 44 24 ?? 41 C6 44 24 ?? 6C C6 44 24 ?? 69 C6 44 24 ?? 63 C6 44 24 ?? 61 C6 44 24 ?? 74 C6 44 24 ?? 69 }
        $a11 = { C6 44 24 ?? 2F C6 44 24 ?? 34 C6 44 24 ?? 2E C6 44 24 ?? 30 C6 44 24 ?? 20 C6 44 24 ?? 28 C6 44 24 ?? 63 }
        $a12 = "%c%c%c%c%c%c" ascii fullword
        $a13 = { 25 2D 32 34 73 20 25 2D 31 35 00 }
    condition:
        5 of them
}