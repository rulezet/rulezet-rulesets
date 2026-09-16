rule sig_20160518_38b4d4024611ebf8710d23d4e1ef870d {
  meta:
    description = "datamaliciousorder - file 20160518_38b4d4024611ebf8710d23d4e1ef870d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42a35f08f4b22dca0e32dca86013d57f6733c8b322da802db6538de67d50971c"

  strings:
    $s1  = "var wallis = [video, wholl,coitus,  \"\"+\".\"+(\"programming\",\"relaxing\",\"syndicate\",\"relax\",\"shirt\",\"insidious\",\"t" ascii
    $s2  = "    erudition.cherub = erudition.login[\"c3Vic3RyaW5n\".crossbow4()](foamy, unapproachable);" fullword ascii
    $s3  = "        var tucker = new uncomfortably(((\"emerald\",\"epidermis\",\"county\",\"blend\",\"written\",\"abroad\",\"encircle\",\"tr" ascii
    $s4  = "            valid[sunder]((\"usury\",\"logan\",\"G\" + weasel) + (\"diploma\",\"compilation\",\"swing\",\"behind\",\"T\"), ostri" ascii
    $s5  = "var hearing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".crossbow4())&&valid[\"c3RhdHVz\".crossbow4()] +\"\"==\"MjAw\".crossb" ascii
    $s6  = "var hearing=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".crossbow4())&&valid[\"c3RhdHVz\".crossbow4()] +\"\"==\"MjAw\".crossb" ascii
    $s7  = "var macromedia = new uncomfortably(terrorist[1]);" fullword ascii
    $s8  = "var valid = new uncomfortably(terrorist[0]);" fullword ascii
    $s9  = "        login: this" fullword ascii
    $s10 = "var terrorist = wallis.pop().split(\">\");" fullword ascii
    $s11 = "        tucker[(desirable + \"o\"+(\"beverage\",\"usury\",\"astrology\",\"soldiery\",\"rapacious\",\"potter\",\"appurtenances\"," ascii
    $s12 = "desirable = ((\"monday\", \"dyspepsia\", \"reseller\", \"bestiality\", \"pnrSqIGoY\") + \"JvjWOMt\").crossbow2();" fullword ascii
    $s13 = "frontier(\"aHR0cDovLw==\".crossbow4()+\"\\u0067\\u0065\\u006E\\u0069\\u0075\\u0073\\u002D\\u0076\\u0065\\u0072\\u0073\\u0061\"+" ascii
    $s14 = "weasel = ((\"goodfellowship\", \"missus\", \"voluntary\", \"personal\", \"EaUOozMAlp\") + \"CwoMowuIX\").crossbow2();" fullword ascii
    $s15 = "String.prototype.crossbow = function () {" fullword ascii
    $s16 = "        var tucker = new uncomfortably(((\"emerald\",\"epidermis\",\"county\",\"blend\",\"written\",\"abroad\",\"encircle\",\"tr" ascii
    $s17 = "var portrait = macromedia[wallis.shift()](wallis.shift());" fullword ascii
    $s18 = "String.prototype.crossbow2 = function () {" fullword ascii
    $s19 = "var uncomfortably = this[wallis.shift()];" fullword ascii
    $s20 = "        tucker[(desirable + \"o\"+(\"beverage\",\"usury\",\"astrology\",\"soldiery\",\"rapacious\",\"potter\",\"appurtenances\"," ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}