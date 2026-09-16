rule Multi_Ransomware_BlackCat_c4b043e6 {
    meta:
        author = "Elastic Security"
        id = "c4b043e6-ff5f-4492-94e3-fd688d690738"
        fingerprint = "3e89858e90632ad5f4831427bd630252113b735c51f7a1aa1eab8ba6e4c16f18"
        creation_date = "2022-09-12"
        last_modified = "2022-09-29"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "45b8678f74d29c87e2d06410245ab6c2762b76190594cafc9543fb9db90f3d4f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a = { 28 4C 8B 60 08 4C 8B 68 10 0F 10 40 28 0F 29 44 24 10 0F 10 }
    condition:
        all of them
}