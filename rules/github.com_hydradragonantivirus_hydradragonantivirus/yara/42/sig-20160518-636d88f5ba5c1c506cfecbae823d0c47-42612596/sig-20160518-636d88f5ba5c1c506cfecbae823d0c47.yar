rule sig_20160518_636d88f5ba5c1c506cfecbae823d0c47 {
  meta:
    description = "datamaliciousorder - file 20160518_636d88f5ba5c1c506cfecbae823d0c47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f7e178003e78300073c0e1709c82246759dbc015caefa14e3650cd0c63e6a8a"

  strings:
    $s1  = "basket = ((\"roulette\", \"hawaii\", \"pentup\", \"centralization\", \"pcXqRaFTp\") + \"GQGtgGoi\").persecute2();" fullword ascii
    $s2  = "var collecting = [marred, statute,tasteful,  \"\"+\".\"+(\"purse\",\"supported\",\"continuous\",\"licentiousness\",\"unpretendin" ascii
    $s3  = "var logistics = collecting.pop().split(\">\");" fullword ascii
    $s4  = "var portmanteau = new consultation(logistics[1]);" fullword ascii
    $s5  = "weasel = ((\"sacrament\", \"bottle\", \"identifies\", \"mourner\", \"EfdWPcnzbmrr\") + \"ULXwVYfKo\").persecute2();" fullword ascii
    $s6  = "var turin=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".persecute4())&&incorporation[\"c3RhdHVz\".persecute4()] +\"\"==\"MjAw" ascii
    $s7  = "var turin=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".persecute4())&&incorporation[\"c3RhdHVz\".persecute4()] +\"\"==\"MjAw" ascii
    $s8  = "var incorporation = new consultation(logistics[0]);" fullword ascii
    $s9  = "discrete = ((\"catalogs\", \"elasticity\", \"denunciation\", \"unconnected\", \"szBQUgkNc\") + \"RcWFEocyKB\").persecute2();" fullword ascii
    $s10 = "        cricket[(basket + \"o\"+(\"apricot\",\"nvidia\",\"ironic\",\"strips\",\"semicircle\",\"expansive\",\"fertilisation\",\"a" ascii
    $s11 = "parasite(\"aHR0cDovLw==\".persecute4()+\"\\u0061\\u0073\\u0068\\u0066\\u006F\\u0072\\u0064\\u0063\\u002E\\u006D\\u0079\\u007A\\u" ascii
    $s12 = "        cricket[(basket + \"o\"+(\"apricot\",\"nvidia\",\"ironic\",\"strips\",\"semicircle\",\"expansive\",\"fertilisation\",\"a" ascii
    $s13 = "String.prototype.persecute2 = function () {" fullword ascii
    $s14 = "var collecting = [marred, statute,tasteful,  \"\"+\".\"+(\"purse\",\"supported\",\"continuous\",\"licentiousness\",\"unpretendin" ascii
    $s15 = "String.prototype.persecute = function () {" fullword ascii
    $s16 = "String.prototype.persecute4 = function() {" fullword ascii
    $s17 = "portmanteau[collecting.shift()](digits, depends, true);" fullword ascii
    $s18 = "        cricket[\"d3JpdGU=\".persecute4()](incorporation[(\"incompatible\",\"fetching\",\"seating\",\"shall\",\"recreation\",\"a" ascii
    $s19 = "atisfied, false);" fullword ascii
    $s20 = "photography = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}