rule Linux_Rootkit_Generic_5d17781b {
    meta:
        author = "Elastic Security"
        id = "5d17781b-5d2a-4405-8806-274e6cabfe2c"
        fingerprint = "220eff54c80a69c3df0d8f71aeacdd114cc2ea0675595c2bfde2ac47578c3a02"
        creation_date = "2024-12-02"
        last_modified = "2025-06-10"
        threat_name = "Linux.Rootkit.Generic"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str = "kallsyms_lookup_name_t"
        $lic1 = "license=Dual BSD/GPL"
        $lic2 = "license=GPL"
    condition:
        $str and 1 of ($lic*)
}