rule sig_20170415_4fa8eb9edfebab3914421c3623516ba6 {
  meta:
    description = "datamaliciousorder - file 20170415_4fa8eb9edfebab3914421c3623516ba6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0100ab900130f7af747656a0d3fbe84b0c17273bef304519ae7a02974a301c8c"

  strings:
    $x1  = "            del[[\"run\"][0]]([DATA(0, \"ve\", [\"cmd.exe /c\"]) + Four(0, \"ng\", [\" \\\"powershell  $nice\"]) + port(0, \"ite" ascii
    $x2  = "            del[[\"run\"][0]]([DATA(0, \"ve\", [\"cmd.exe /c\"]) + Four(0, \"ng\", [\" \\\"powershell  $nice\"]) + port(0, \"ite" ascii
    $s3  = "rep(0, \"dark\", [\"pass -\"]) + how(0, \"Area\", [\"Scop';$to\"]) + year(0, \"f463\", [\"=\"]) + Save(0, \"LINE\", [\"'^meskolz" ascii
    $s4  = "ownl'\"]) + h5(0, \"sl\", [\";$Full='^e Pro'\"]) + e179(0, \"gz\", [\";$eur='^Set-Executi\"]) + j(0, \"lgpl\", [\"onPoli'\"]) + " ascii
    $s5  = "var far = 'WScript.Shell'; /* the revolutionary ideas of Strasser, but added that if the  */" fullword ascii
    $s6  = "[\"NONE='^m\"]) + Novo(0, \"hy\", [\"p+''\\\\';$Za='^e1\"]) + able(0, \"Vary\", [\"51.';$sg='^oadFil\"]) + IMG(0, \"YYYY\", [\"e" ascii
    $s7  = "es(0, \"Or\", [\"Team+$dirs+$oj+$ru\"]) + USED(0, \"five\", [\"+$rea\"]) + uk(0, \"bits\", [\"l\"]) + Prep(0, \"pasv\", [\");" ascii
    $s8  = "} /* sequence of a complete lack of all psychologically suitable  */" fullword ascii
    $s9  = "// things did not differ by a hair's breadth. <* " fullword ascii
    $s10 = "\", [\";$Eu='^'',$p';$Eac\"]) + Pull(0, \"d3\", [\"h='^t System.N\"]) + o(0, \"Twi\", [\"';$Team='^ath);\"]) + odd(0, \"odt\", [" ascii
    $s11 = "function alt(LOG, Does, life) {" fullword ascii
    $s12 = "function org(none, grav, log) {" fullword ascii
    $s13 = "function Pull(FOR, XML, IRC) {" fullword ascii
    $s14 = "function e057(tmce, Weed, Get) {" fullword ascii
    $s15 = "function e179(Stop, conf, Logo) {" fullword ascii
    $s16 = "c(0, \"Info\", [\"n ($eur+$jkw+$Full+\"]) + _hsv(0, \"ximg\", [\"$eq+$NON\"]) + rain(0, \"or\", [\"E+$Za+$e013\"]) + org(0, \"sc" ascii
    $s17 = "} /* what the movement wanted to fight most sharply, namely,  */" fullword ascii
    $s18 = ", \"Acre\", [\"/use';$e013='^ex\"]) + Bar(0, \"auto\", [\"e'');(\"]) + With(0, \"LEFT\", [\"New-Objec';$oj='^p\"]) + MD5(0, \"Po" ascii
    $s19 = "} /* THERE are two reasons which induce me to subject the  */" fullword ascii
    $s20 = "} /* himself appear always as the 'pure 1 one and to charge the  */" fullword ascii

  condition:
    uint16(0) == 0x2f2f and
    1 of ($x*) and 4 of them
}