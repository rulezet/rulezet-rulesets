rule INDICATOR_KB_ID_Ransomware_STOP {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with STOP ransomware"
    strings:
        $s1 = "gorentos@bitmessage.ch" ascii wide nocase
        $s2 = "gorentos2@firemail.cc" ascii wide nocase
        $s3 = "manager@mailtemp.ch" ascii wide nocase
        $s4 = "helprestoremanager@airmail.cc" ascii wide nocase
        $s5 = "supporthelp@airmail.cc" ascii wide nocase
        $s6 = "managerhelper@airmail.cc" ascii wide nocase
        $s7 = "helpteam@mail.ch" ascii wide nocase
        $s8 = "helpmanager@airmail.cc" ascii wide nocase
        $s9 = "support@sysmail.ch" ascii wide nocase
    condition:
        any of them
}