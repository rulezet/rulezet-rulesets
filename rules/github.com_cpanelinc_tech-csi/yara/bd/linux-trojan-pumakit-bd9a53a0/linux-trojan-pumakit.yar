rule Linux_Trojan_Pumakit {
    meta:
        author = "Elastic Security"
        creation_date = "2024-12-09"
        last_modified = "2024-12-09"
        os = "Linux"
        arch = "x86, arm64"
        threat_name = "Linux.Trojan.Pumakit"
    strings:
        $str1 = "PUMA %s"
        $str2 = "Kitsune PID %ld"
        $str3 = "/usr/share/zov_f"
        $str4 = "zarya"
        $str5 = ".puma-config"
        $str6 = "ping_interval_s"
        $str7 = "session_timeout_s"
        $str8 = "c2_timeout_s"
        $str9 = "LD_PRELOAD=/lib64/libs.so"
        $str10 = "kit_so_len"
        $str11 = "opsecurity1.art"
        $str12 = "89.23.113.204"
    condition:
        4 of them
}