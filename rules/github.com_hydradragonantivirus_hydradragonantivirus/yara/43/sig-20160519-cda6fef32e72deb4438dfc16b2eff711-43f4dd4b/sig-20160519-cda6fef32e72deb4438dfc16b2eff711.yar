rule sig_20160519_cda6fef32e72deb4438dfc16b2eff711 {
  meta:
    description = "datamaliciousorder - file 20160519_cda6fef32e72deb4438dfc16b2eff711.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00923c7db51cbb41db3ce3c931bebcf5aa279934989774c56bbfd3f84d0f1cfa"

  strings:
    $s1  = "var incubus = [diane, breton,gravy,  \"\"+\".\"+(\"cocktail\",\"tokyo\",\"residential\",\"gradually\",\"bottomless\",\"adjustabl" ascii
    $s2  = "var talmud=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".embassy4())&&darkness[\"c3RhdHVz\".embassy4()] +\"\"==\"MjAw\".embass" ascii
    $s3  = "var talmud=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".embassy4())&&darkness[\"c3RhdHVz\".embassy4()] +\"\"==\"MjAw\".embass" ascii
    $s4  = "weasel = ((\"apache\", \"suzerain\", \"shape\", \"terror\", \"ECDSoYHjx\") + \"DyQmDzpOQ\").embassy2();" fullword ascii
    $s5  = "privy = ((\"eagle\", \"peevish\", \"dimmer\", \"disdainful\", \"reform\", \"looped\", \"scRzFoSyIn\") + \"uUnYBsGc\").embassy2()" ascii
    $s6  = "consultation = consultation+ incubus.shift();" fullword ascii
    $s7  = "smoothness(\"aHR0cDovLw==\".embassy4()+\"\\u0064\\u0065\\u006E\\u007A\\u0069\\u006C\\u002E\\u0063\\u006F\\u006D\\u002E\"+\"\\u00" ascii
    $s8  = "    darkness[privy + (\"membership\",\"confounding\",\"end\")]();" fullword ascii
    $s9  = "String.prototype.embassy4 = function() {" fullword ascii
    $s10 = "String.prototype.embassy = function () {" fullword ascii
    $s11 = "String.prototype.embassy2 = function () {" fullword ascii
    $s12 = "var darkness = new designer(britannica[0]);" fullword ascii
    $s13 = "e, false);" fullword ascii
    $s14 = "defendant = \"_F2_\";" fullword ascii
    $s15 = "irreligious[incubus.shift()](consultation, truss, true);" fullword ascii
    $s16 = "            darkness[strategies]((\"omniscient\",\"fearsome\",\"G\" + weasel) + (\"lincoln\",\"represent\",\"bubble\",\"fibrous" ascii
    $s17 = "smoothness(\"aHR0cDovLw==\".embassy4()+\"\\u0064\\u0065\\u006E\\u007A\\u0069\\u006C\\u002E\\u0063\\u006F\\u006D\\u002E\"+\"\\u00" ascii
    $s18 = "        permission[\"d3JpdGU=\".embassy4()](darkness[(\"lower\",\"encoding\",\"phosphorescence\",\"illimitable\",\"pedestal\",\"" ascii
    $s19 = "  enumeration = [];" fullword ascii
    $s20 = "for (var i in admissible){abhor = abhor.replace(i, admissible[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}