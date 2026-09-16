rule Windows_Trojan_OtterCookie_ae33e607 {
    meta:
        author = "Elastic Security"
        id = "ae33e607-5ed5-4259-9a51-dd011f911b11"
        fingerprint = "e1148316c1e21444352e4683d650eac6b36e1d0e9a3da448895c8a59bb33f65d"
        creation_date = "2026-07-13"
        last_modified = "2026-07-15"
        threat_name = "Windows.Trojan.OtterCookie"
        reference_sample = "b8a4d8bf5912df9435e3fa98cfff0fb4b2c38cff1bb4eda3ef632db8c729aa15"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "isFile" ascii wide
        $b = "isDirectory" ascii wide
        $c = "wmic logicaldisk get name" ascii wide
        $d = "excludeFolders" ascii wide
        $e = "else await scanDir(rootDir)" ascii wide
    condition:
        4 of them
}