rule sig_20160517_32df685bb4d53431b2a361a2343d24c1 {
  meta:
    description = "datamaliciousorder - file 20160517_32df685bb4d53431b2a361a2343d24c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f040518f4c7020e15c0e4456f22a62e3a310950bcdb03c1ba8a8c3e94187404"

  strings:
    $s1  = "var measurable = [minerals, larynx,thrall,  \"\"+\".\"+(\"taboo\",\"puddle\",\"gender\",\"notoriety\",\"duncan\",\"follow\",\"je" ascii
    $s2  = "var devil = {" fullword ascii
    $s3  = "ment\",\"s\")+\"ubRt\"+(\"ensue\",\"evergreen\",\"hayes\",\"elector\",\"straight\",\"thump\",\"holds\",\"ri\")+\"ng\").replace(" ascii
    $s4  = "for (var i in devil){asked = asked.replace(i, devil[i]);}" fullword ascii
    $s5  = "    techrepublic.educator = techrepublic.graphs[((\"mysql\",\"julian\",\"adornment\",\"elegy\",\"dance\",\"acidity\",\"biotechno" ascii
    $s6  = "filled = filled+ measurable.shift();" fullword ascii
    $s7  = "obdurate = ((\"autem\", \"happening\", \"incoherent\", \"commerce\", \"sBVcfkRLhVYL\") + \"fpXBQykojA\").vocals2();" fullword ascii
    $s8  = "common = \"_F2_\";" fullword ascii
    $s9  = "var coerce = measurable.pop().split(\"" fullword ascii
    $s10 = "ess\",\"marketing\",\"legitimately\",\"fervor\",\"biblical\",\"phoenicia\",\"ip\")+\"t:\"+(\"telecharger\",\"brewed\",\"milky\"," ascii
    $s11 = "var testing=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vocals4())&&printing[\"c3RhdHVz\".vocals4()] +\"\"==\"MjAw\".vocals4" ascii
    $s12 = "var testing=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vocals4())&&printing[\"c3RhdHVz\".vocals4()] +\"\"==\"MjAw\".vocals4" ascii
    $s13 = "        var locus = new finance(((\"unmerciful\",\"cyprus\",\"expert\",\"evenly\",\"unconcerned\",\"chaldea\",\"falling\",\"gadg" ascii
    $s14 = "var infinite = 0;" fullword ascii
    $s15 = "relation\",\"unsound\",\"unkempt\",\"setup\",\"08\"), obdurate)] = 0;" fullword ascii
    $s16 = "        var locus = new finance(((\"unmerciful\",\"cyprus\",\"expert\",\"evenly\",\"unconcerned\",\"chaldea\",\"falling\",\"gadg" ascii
    $s17 = "var handed = funereal[measurable.shift()](measurable.shift());" fullword ascii
    $s18 = "var funereal = new finance(coerce[1]);" fullword ascii
    $s19 = "var printing = new finance(coerce[0]);" fullword ascii
    $s20 = "weasel = ((\"synopsis\", \"rejected\", \"mitigation\", \"criteria\", \"ExaSJLm\") + \"bPNtBUO\").vocals2();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}