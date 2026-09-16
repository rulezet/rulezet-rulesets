rule M_Hunting_TINYSHELL_5 {
    meta:
        author = "Mandiant"
    strings:
        $tsh_1 = "tsh_get_file"
        $tsh_2 = "tsh_put_file"
        $tsh_3 = "tsh_runshell"
        $tshd_1 = "tshd_get_file"
        $tshd_2 = "tshd_put_file"
        $tshd_3 = "tshd_runshell"
    condition:
        all of ($tshd_*) or all of ($tsh_*)
}