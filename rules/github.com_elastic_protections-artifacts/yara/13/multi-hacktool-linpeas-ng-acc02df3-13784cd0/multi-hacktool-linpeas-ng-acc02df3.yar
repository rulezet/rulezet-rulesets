rule Multi_Hacktool_LinPEAS_ng_acc02df3 {
    meta:
        author = "Elastic Security"
        id = "acc02df3-8a22-4fe7-83ec-6810b7933d7a"
        fingerprint = "f55005da8a884e05627a511d8aa065ffdac40a947293a95bd754eda268e407c6"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Base module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $base_0 = "$(printf '\\033')"
        $base_1 = "Enumerate and search Privilege Escalation vectors."
        $base_2 = "grep -c processor /proc/cpuinfo"
        $base_3 = "Do you like PEASS?"
        $base_4 = "RED/YELLOW: 95% a PE vector"
        $base_5 = "\\(root\\)|\\(shadow\\)|\\(admin\\)|\\(video\\)|\\(adm\\)|\\(wheel\\)|\\(auth\\)"
        $base_6 = "peass{SUIDVB1_HERE}"
        $base_7 = "file|free|main|more|read|split|write"
        $base_8 = "cap_sys_admin:mount|python"
        $base_9 = "timeout 1 su $(whoami) -c whoami"
    condition:
        5 of them
}