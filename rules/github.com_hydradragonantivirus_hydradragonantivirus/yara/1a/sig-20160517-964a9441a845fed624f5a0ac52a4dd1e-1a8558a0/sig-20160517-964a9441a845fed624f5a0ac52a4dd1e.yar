rule sig_20160517_964a9441a845fed624f5a0ac52a4dd1e {
  meta:
    description = "datamaliciousorder - file 20160517_964a9441a845fed624f5a0ac52a4dd1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85e9ad7d850e44ea516911340e272e77fc77f63a8148a77a1ceb870ea53d2900"

  strings:
    $s1 = "var ua41='vm1smtaeyc44rwjjrz lrhesdavbjd1hzfpopknp14xfk3oofat2pkezlbit3wvoafmxafbu=njhmj\\'pzynntwthpicspx33ng2yfbidafmgfgkul2uq" ascii
    $s2 = "\"xp\");   pr2islia=r4+\"v\"+\"al\";   WScript.lister=5;   pr2islia=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"+" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}