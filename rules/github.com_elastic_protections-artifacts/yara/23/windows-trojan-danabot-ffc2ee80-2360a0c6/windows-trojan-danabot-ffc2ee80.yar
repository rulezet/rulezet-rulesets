rule Windows_Trojan_Danabot_ffc2ee80 {
    meta:
        author = "Elastic Security"
        id = "ffc2ee80-63ce-4473-8cb6-b226c9de2919"
        fingerprint = "3fa382f55cbd8c59ce1fb02d49940718947f514a0fbca5681aef3c54d8dbd251"
        creation_date = "2025-11-11"
        last_modified = "2026-01-06"
        threat_name = "Windows.Trojan.Danabot"
        reference_sample = "40d4cd5109435eaf242aa03a2c34efa87c06c9450b3d90b6f8ef7dcb161fb864"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = "S-Password" wide fullword
        $a2 = "data_inject_on" wide fullword
        $a3 = "BiosTime:" wide fullword
        $a4 = "%BOT_ID%" wide fullword
        $a5 = "%BOT_VERSION%" wide fullword
        $a6 = "DanaBot_" wide
    condition:
        5 of them
}