rule INDICATOR_KB_ID_Ransomware_Maze {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with Maze ransomware"
    strings:
        $s1 = "getmyfilesback@airmail.cc" ascii wide nocase
    condition:
        any of them
}