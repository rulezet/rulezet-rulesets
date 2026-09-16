rule locky_panel__bitcoins : malware
{
    meta:
        description = "Identify locky/ransomware panel on the bitcoins handling"
        author = "@h3x2b <tracker _AT h3x.eu>"
                
    strings:
        $s01 = "registered"
        $s02 = "visited"
        $s03 = "ip"
        $s04 = "affid"
        $s05 = "completed"
        $s06 = "lang"
        $s07 = "is_server"
        $s08 = "corporate"
        $s09 = "os_ver"
        $s10 = "is_x64"
        $s11 = "btc_address"
        $s12 = "btc_needed"
        $s13 = "btc_payed"
        $s14 = "txfree"
        $s15 = "txid"

    condition:
        all of them

}