rule Linux_Hacktool_Outlaw_bc128a02 {
    meta:
        author = "Elastic Security"
        id = "bc128a02-ee4e-484d-ae94-9e5cf1d26e94"
        fingerprint = "7dbce4ec62eac61115a98bcf0703bfddf684e54adef2b17d31a88cdfbf52e23c"
        creation_date = "2025-02-21"
        last_modified = "2025-03-07"
        description = "Socat wrapper found in one of the versions of the outlaw Dota3 package"
        threat_name = "Linux.Hacktool.Outlaw"
        reference_sample = "008eadac3de35c5d4cd46ec00eb3997ff4c2fe864232fff5320b2697de7116cd"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str_1 = ".templock"
        $str_2 = "Selected IP: %s\n"
        $str_3 = "Connection is working! #########"
        $str_4 = "Killed all socat processes using 'pkill -9 socat'."
        $str_5 = "socat process is running! (PID: %d)\n"
        $str_6 = "Connection to %s:%d is working!\n"
    condition:
        5 of them
}