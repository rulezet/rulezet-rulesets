rule sig_20160518_cdfc84c8bcc78a7c8e854d96169d9c50 {
  meta:
    description = "datamaliciousorder - file 20160518_cdfc84c8bcc78a7c8e854d96169d9c50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f37b7a7a5823e6e3d34ad734abe4f3a1fcb220c90786249551558a415aa633f"

  strings:
    $s1  = "tarded\",\"sporting\",\"migrate\",\"puddles\",\"majordomo\",\"astral\",\"08\"), hackneyed)] = 0;" fullword ascii
    $s2  = "var circlet = heifer.pop().split(\">\");" fullword ascii
    $s3  = "var stephanie=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".medley4())&&equilibrium[\"c3RhdHVz\".medley4()] +\"\"==\"MjAw\".me" ascii
    $s4  = "var stephanie=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".medley4())&&equilibrium[\"c3RhdHVz\".medley4()] +\"\"==\"MjAw\".me" ascii
    $s5  = "var equilibrium = new bangbus(circlet[0]);" fullword ascii
    $s6  = "var heifer = [gloating, valid,marshall,  \"\"+\".\"+(\"oliver\",\"expire\",\"indexes\",\"policies\",\"obnoxious\",\"playmate\"," ascii
    $s7  = "hackneyed = ((\"roman\", \"bargain\", \"conditional\", \"metrical\", \"sCoPSiErgwmM\") + \"QuxHjA\").medley2();" fullword ascii
    $s8  = "var locust = new bangbus(circlet[1]);" fullword ascii
    $s9  = "pledge = pledge+ heifer.shift();" fullword ascii
    $s10 = "weasel = ((\"result\", \"acclaim\", \"maize\", \"shorthand\", \"ELCyYJSvOuyC\") + \"XpPBflRwoG\").medley2();" fullword ascii
    $s11 = "transcendental = ((\"homemade\", \"supply\", \"adviser\", \"milestone\", \"prUEwWG\") + \"FOWkazOW\").medley2();" fullword ascii
    $s12 = "    equilibrium[hackneyed + (\"relay\",\"brigantine\",\"end\")]();" fullword ascii
    $s13 = "String.prototype.medley2 = function () {" fullword ascii
    $s14 = "String.prototype.medley = function () {" fullword ascii
    $s15 = "var authoritative = locust[heifer.shift()](heifer.shift());" fullword ascii
    $s16 = "String.prototype.medley4 = function() {" fullword ascii
    $s17 = "        promotes[(transcendental + \"o\"+(\"reliance\",\"wesley\",\"appealingly\",\"minion\",\"thrifty\",\"mishap\",\"proverbs\"" ascii
    $s18 = "        var pledge = authoritative + \"/\" + masturbation ;" fullword ascii
    $s19 = "var bangbus = this[heifer.shift()];" fullword ascii
    $s20 = "            equilibrium[woodwork]((\"stumble\",\"unions\",\"G\" + weasel) + (\"renewable\",\"scuttle\",\"interlude\",\"physiolog" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}