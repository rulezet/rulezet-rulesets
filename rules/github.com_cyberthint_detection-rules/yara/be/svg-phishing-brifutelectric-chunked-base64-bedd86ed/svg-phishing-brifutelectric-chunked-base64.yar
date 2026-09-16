rule SVG_Phishing_Brifutelectric_Chunked_Base64 {
    meta:
        description = "Detects the chunked Base64 pattern used in the SVG phishing campaign"
        date = "2026-03-12"
        severity = "HIGH"
    
    strings:
        $chunk1 = "aH" ascii
        $chunk2 = "R0" ascii
        $chunk3 = "cH" ascii
        $chunk4 = "M6" ascii
        $chunk5 = "Ly" ascii
        $chunk6 = "9q" ascii
        $chunk7 = "cy" ascii
        $chunk8 = "5w" ascii
        $chunk9 = "b2" ascii
        $chunk10 = "9j" ascii
        $chunk11 = "aG" ascii
        $chunk12 = "Vh" ascii
        $chunk13 = "c3" ascii
        $chunk14 = "Rh" ascii
        $chunk15 = "Lm" ascii
        $chunk16 = "Jp" ascii
        $chunk17 = "ei" ascii
        $chunk18 = "bC" ascii
        $chunk19 = "9Q" ascii
        $chunk20 = "bH" ascii
        $chunk21 = "dD" ascii
        $chunk22 = "Vm" ascii
        $chunk23 = "5I" ascii
        $chunk24 = "NU" ascii
        $chunk25 = "E5" ascii
        $chunk26 = "QG" ascii
        $chunk27 = "lp" ascii
        $chunk28 = "Lw" ascii
        $chunk29 = "==" ascii
    
    condition:
        10 of them and filesize < 10KB
}