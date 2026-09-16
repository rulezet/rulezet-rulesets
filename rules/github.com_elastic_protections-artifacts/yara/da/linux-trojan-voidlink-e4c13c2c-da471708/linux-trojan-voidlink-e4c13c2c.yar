rule Linux_Trojan_VoidLink_e4c13c2c {
    meta:
        author = "Elastic Security"
        id = "e4c13c2c-2813-4942-93a1-1bed72ad3c7d"
        fingerprint = "246e070f045575cf044eb20607001cac3f8a1704ee71bd052ac9d2bc231fd406"
        creation_date = "2026-01-15"
        last_modified = "2026-03-10"
        description = "Detects the VoidLink Plugins"
        threat_name = "Linux.Trojan.VoidLink"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $name = "VoidLink"
        $str_b = "BeaconAPI_v3"
        $str_c = "[PLUGIN_EXEC]"
        $str_d = "parallel_executed"
        $str_e = "[ChainExecutor]"
        $str_f = "[PARSE_SHDR]"
        $str_g = "ShellcodeTimeout"
        $str_h = "camouflage executor"
        $str_i = "anti-reverse executor"
    condition:
        $name and 5 of ($str_*)
}