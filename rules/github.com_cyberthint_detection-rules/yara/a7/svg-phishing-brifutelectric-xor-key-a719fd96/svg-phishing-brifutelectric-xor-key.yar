rule SVG_Phishing_Brifutelectric_XOR_Key {
    meta:
        description = "Detects the XOR key used in the SVG phishing campaign"
        date = "2026-03-12"
        severity = "HIGH"
    
    strings:
        $xp = "6795a9a72428" ascii
        $qc = "93e6ef978723" ascii
        $fb = "6795a9a7242893e6ef978723" ascii
    
    condition:
        ($xp and $qc) or $fb
}