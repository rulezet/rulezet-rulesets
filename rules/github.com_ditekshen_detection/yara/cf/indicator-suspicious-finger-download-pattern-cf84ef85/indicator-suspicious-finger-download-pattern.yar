rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,10}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}