rule INDICATOR_KB_ID_Ransomware_PYSA {
    meta:
        author = "ditekShen"
        description = "Detects files referencing identities associated with PYSA / Mespinoza ransomware"
    strings:
        $s1 = "luebegg8024@onionmail.org" ascii wide nocase
        $s2 = "mayakinggw3732@onionmail.org" ascii wide nocase
        $s3 = "lauriabornhat7722@protonmail.com" ascii wide nocase
        $s4 = "DeborahTrask@onionmail.org" ascii wide nocase
        $s5 = "AlisonRobles@onionmail.org" ascii wide nocase
        $s6 = "NatanSchultz67@protonmail.com" ascii wide nocase
        $s7 = "jonikemppi@onionmail.org" ascii wide nocase
        $s8 = "lanerosalie49003@onionmail.org" ascii wide nocase
        $s9 = "bernalmargaret645@onionmail.org" ascii wide nocase
        $s10 = "carlhubbard2021@protonmail.com" ascii wide nocase
        $u1 = "http://pysa2bitc" ascii wide
    condition:
        any of them
}