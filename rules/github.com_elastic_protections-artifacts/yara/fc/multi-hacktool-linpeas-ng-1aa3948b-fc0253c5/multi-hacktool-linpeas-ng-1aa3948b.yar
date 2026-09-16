rule Multi_Hacktool_LinPEAS_ng_1aa3948b {
    meta:
        author = "Elastic Security"
        id = "1aa3948b-a742-40d1-9f06-7f33260206a7"
        fingerprint = "4b2367262369a0dfe1320e9d4f60a7736c47ef6cefab3966561d8746605ee14f"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Software info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $software_0 = "Installed Compilers"
        $software_1 = "$(command -v pkg 2>/dev/null)"
        $software_2 = "$(command -v mysqladmin)"
        $software_3 = "MySQL version"
        $software_4 = "SELECT User,Host,authentication_string FROM"
        $software_5 = "Some certificates were found (out limited):"
        $software_6 = "keyinfo --list"
        $software_7 = "You could use SSSDKCMExtractor to"
        $software_8 = "LS_USER\\|LS_GROUP"
        $software_9 = "Searching tmux sessions"
    condition:
        5 of them
}