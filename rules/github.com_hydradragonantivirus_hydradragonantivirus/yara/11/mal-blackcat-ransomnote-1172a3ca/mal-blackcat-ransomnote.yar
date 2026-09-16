rule MAL_BlackCat_ransomnote {
    meta:
        description = "Matches strings found in two versions of ransom notes dropped by BlackCat (ALPHV)."
        last_modified = "2024-01-16"
        author = "@petermstewart"
        DaysofYara = "16/100"

    strings:
        $heading1a = ">> What happened?"
        $heading1b = ">> Introduction"
        $heading2 = ">> Sensitive Data"
        $heading3 = ">> CAUTION"
        $heading4a = ">> What should I do next?"
        $heading4b = ">> Recovery procedure"
        $a1 = "In order to recover your files you need to follow instructions below."
        $a2 = "clients data, bills, budgets, annual reports, bank statements"
        $a3 = "1) Download and install Tor Browser from: https://torproject.org/"
        $a4 = "2) Navigate to: http://"

    condition:
        filesize < 5KB and
        ($heading1a and $heading4a) or ($heading1b and $heading4b) and
        $heading2 and $heading3 and 
        all of ($a*)
}