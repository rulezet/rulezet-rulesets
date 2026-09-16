rule Windows_Trojan_RevStealer_295fca7e {
    meta:
        author = "Elastic Security"
        id = "295fca7e-4478-4b27-916c-9c6659fe25ea"
        fingerprint = "cd6163fc572cfd89a15cc36d9147b534e2af83ab0fdc49e22479b1a4d84c843a"
        creation_date = "2026-08-28"
        last_modified = "2026-09-01"
        description = "Identifies WinUpdate module"
        threat_name = "Windows.Trojan.RevStealer"
        reference_sample = "7c08cf409194056a8517865e5d3433d1499bb8262263b55b49b8b07d9d182fcb"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 49 8B D3 49 8B C8 49 2B D0 48 8B FB 8A 04 0A 88 01 48 FF C1 48 83 EF 01 }
        $b = { 41 0F B7 04 09 FF C2 66 89 01 49 FF C3 48 83 C1 02 4D 3B DA }
    condition:
        any of them
}