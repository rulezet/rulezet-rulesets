rule locky_panel__dbaccess : malware
{
    meta:
        description = "Identify locky/ransomware panel in php"
        author = "@h3x2b <tracker _AT h3x.eu>"
                            
    strings:
        $s01 = "userinfo"
        $s02 = "db_query_single"
        $s03 = "SELECT * FROM users WHERE id=?"
        $s04 = "SESSION['uid']"
        $s05 = "goto not_logged_in"
        $s06 = "SELECT id,pass,enabled FROM users WHERE name=?"
        $s07 = "count(id) as Total"
        $s08 = "count(NULLIF(completed,0)) as Completed"
        $s09 = "count(NULLIF(btc_payed,0)) as Paid"
        $s10 = "sum(btc_payed)"
        $s11 = "Amount BTC"
        $s12 = "SELECT affid as User"
        $s13 = "columns FROM clients GROUP BY affid"
        $s14 = "format_btc(strval("
        
    condition:
        all of them

}