rule Multi_Hacktool_LinPEAS_ng_3e7102db {
    meta:
        author = "Elastic Security"
        id = "3e7102db-69e1-45f1-8258-7a1a40e95e45"
        fingerprint = "098396bdcd0b0f83d8064ec4bd26974abdcf5b1d5bb2abd0ef748cf788c5526e"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Software info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $software_0 = "Installed Compilers" base64
        $software_1 = "$(command -v pkg 2>/dev/null)" base64
        $software_2 = "$(command -v mysqladmin)" base64
        $software_3 = "MySQL version" base64
        $software_4 = "SELECT User,Host,authentication_string FROM" base64
        $software_5 = "Some certificates were found (out limited):" base64
        $software_6 = "keyinfo --list" base64
        $software_7 = "You could use SSSDKCMExtractor to" base64
        $software_8 = "LS_USER\\|LS_GROUP" base64
        $software_9 = "Searching tmux sessions" base64
    condition:
        5 of them
}