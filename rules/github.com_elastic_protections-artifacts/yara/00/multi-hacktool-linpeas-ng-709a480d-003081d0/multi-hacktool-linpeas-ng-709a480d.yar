rule Multi_Hacktool_LinPEAS_ng_709a480d {
    meta:
        author = "Elastic Security"
        id = "709a480d-f797-4ad0-a67b-6e4b814ffc18"
        fingerprint = "06af5a1d00998d44113c69b5bcf494bbda52ffc63b1013681d46d2122545cded"
        creation_date = "2022-12-21"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Processes & Cron & Services & Timers module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $cron_0 = "Looks like ps is not finding processes" base64
        $cron_1 = "(ps fauxwww || ps auxwww | sort ) 2>/dev/null | grep -v \"\\[\" | grep -v \"%CPU\"" base64
        $cron_2 = "/dev/null | grep CapEff | awk" base64
        $cron_3 = "awk '!x[$0]++' 2>/dev/null | grep -v \" root root \"" base64
        $cron_4 = "Files opened by processes belonging to other users" base64
        $cron_5 = "gdm-password process found (dump creds from memory as root)" base64
        $cron_6 = "-name \"cron*\" -or -name \"anacron\" -or -name \"anacrontab\"" base64
        $cron_7 = "/Library/LaunchDaemons/MonitorHelper.plist ProgramArguments" base64
        $cron_8 = "SPStartupItemDataType" base64
        $cron_9 = "Unix Sockets Listening" base64
    condition:
        5 of them
}