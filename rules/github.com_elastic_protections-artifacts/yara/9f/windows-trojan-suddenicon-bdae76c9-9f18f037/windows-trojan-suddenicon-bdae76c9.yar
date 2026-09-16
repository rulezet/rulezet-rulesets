rule Windows_Trojan_SuddenIcon_bdae76c9 {
    meta:
        author = "Elastic Security"
        id = "bdae76c9-ee1d-4acc-9b1a-4123763ea1b8"
        fingerprint = "8ab0495b59eb84e5506a740a9055c3ec75f25e564761c26f4d829d4ec420a5cf"
        creation_date = "2024-12-16"
        last_modified = "2025-02-11"
        threat_name = "Windows.Trojan.SuddenIcon"
        reference_sample = "11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $hex_sig = { FE ED FA CE FE ED FA CE }
        $str1 = "D3DCompiler_47.pdb" ascii fullword
    condition:
        all of them
}