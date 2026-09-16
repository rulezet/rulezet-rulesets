rule Multi_Hacktool_LinPEAS_ng_02c12676 {
    meta:
        author = "Elastic Security"
        id = "02c12676-4101-44ae-be7c-d93717d04b0a"
        fingerprint = "e2e1233f5c9f24da37e1abf2c216c31505fd3f061bd0228c2c6da9036f3c863b"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Base module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $base_0 = "$(printf '\\033')" base64
        $base_1 = "Enumerate and search Privilege Escalation vectors." base64
        $base_2 = "grep -c processor /proc/cpuinfo" base64
        $base_3 = "Do you like PEASS?" base64
        $base_4 = "RED/YELLOW: 95% a PE vector" base64
        $base_5 = "\\(root\\)|\\(shadow\\)|\\(admin\\)|\\(video\\)|\\(adm\\)|\\(wheel\\)|\\(auth\\)" base64
        $base_6 = "peass{SUIDVB1_HERE}" base64
        $base_7 = "file|free|main|more|read|split|write" base64
        $base_8 = "cap_sys_admin:mount|python" base64
        $base_9 = "timeout 1 su $(whoami) -c whoami" base64
    condition:
        5 of them
}