rule Multi_Hacktool_LinPEAS_ng_46488ab2 {
    meta:
        author = "Elastic Security"
        id = "46488ab2-093f-4371-b806-00e1df5c144e"
        fingerprint = "d12007aa8b6ad1dea30a46fb2b3d39b3a77ef18f6a2ecf6756a6a997e22ccb05"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Processes & Cron & Services & Timers module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cron_0 = "Looks like ps is not finding processes"
        $cron_1 = "(ps fauxwww || ps auxwww | sort ) 2>/dev/null | grep -v \"\\[\" | grep -v \"%CPU\""
        $cron_2 = "/dev/null | grep CapEff | awk"
        $cron_3 = "awk '!x[$0]++' 2>/dev/null | grep -v \" root root \""
        $cron_4 = "Files opened by processes belonging to other users"
        $cron_5 = "gdm-password process found (dump creds from memory as root)"
        $cron_6 = "-name \"cron*\" -or -name \"anacron\" -or -name \"anacrontab\""
        $cron_7 = "/Library/LaunchDaemons/MonitorHelper.plist ProgramArguments"
        $cron_8 = "SPStartupItemDataType"
        $cron_9 = "Unix Sockets Listening"
    condition:
        5 of them
}