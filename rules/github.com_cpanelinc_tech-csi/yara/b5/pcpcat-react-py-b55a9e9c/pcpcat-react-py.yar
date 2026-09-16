rule PCPcat_react_py {
    meta:
        description = "PCPcat React.py scanner"
        author = "Threat Intel"
        date = "2025-12-14"
    strings:
        $s1 = "CVE-2025-29927" nocase
        $s2 = "PCPcat" nocase
        $s3 = "67.217.57.240:5656" nocase
        $s4 = "deploy_pcpcat"
        $s5 = "extract .env"
    condition:
        (2 of them)
}