rule sig_20160516_9752f8f61bf312abbee7413d026e75a5 {
  meta:
    description = "datamaliciousorder - file 20160516_9752f8f61bf312abbee7413d026e75a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c36cf56ed945226f15d666193d61a9257f2f026405eeccd7e2e0a83ea889bb5d"

  strings:
    $s1  = "compiler = ((\"selfevident\", \"works\", \"bondage\", \"tonguetied\", \"pzCYKiWtF\") + \"PKqNxH\").advertisers2();" fullword ascii
    $s2  = "var belly=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".advertisers4())&&silent[\"c3RhdHVz\".advertisers4()] +\"\"==\"MjAw\".a" ascii
    $s3  = "var belly=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".advertisers4())&&silent[\"c3RhdHVz\".advertisers4()] +\"\"==\"MjAw\".a" ascii
    $s4  = "weasel = ((\"linear\", \"different\", \"faulty\", \"purposeless\", \"EkgpVUn\") + \"vYoTkXwAAR\").advertisers2();" fullword ascii
    $s5  = "morale = morale+ regular.shift();" fullword ascii
    $s6  = "String.prototype.advertisers = function () {" fullword ascii
    $s7  = "String.prototype.advertisers4 = function() {" fullword ascii
    $s8  = "var pugnacious = regular.pop().split(\"" fullword ascii
    $s9  = "productivity\",\"s\")+\"ubRt\"+(\"comma\",\"pickled\",\"waylaid\",\"versus\",\"chlorine\",\"zigzag\",\"snipe\",\"ri\")+\"ng\").r" ascii
    $s10 = "String.prototype.advertisers2 = function () {" fullword ascii
    $s11 = "    return rattlesnake.commission;" fullword ascii
    $s12 = "        virginity[(compiler + \"o\"+(\"functioning\",\"zoning\",\"memoir\",\"beautiful\",\"proceed\",\"remarkable\",\"resists\"," ascii
    $s13 = "var regular = [dreads, award,firefox,  \"\"+\".\"+(\"schism\",\"revision\",\"brook\",\"carcass\",\"defeat\",\"accredited\",\"pho" ascii
    $s14 = "        virginity[(compiler + \"o\"+(\"functioning\",\"zoning\",\"memoir\",\"beautiful\",\"proceed\",\"remarkable\",\"resists\"," ascii
    $s15 = "fluffy = \"b3Blbg==\".advertisers4();;" fullword ascii
    $s16 = "investigation = ((\"separates\", \"catholic\", \"mason\", \"voiceless\", \"sRLVDbxrSvm\") + \"gVFQvv\").advertisers2();" fullword ascii
    $s17 = "        var virginity = new another(((\"spine\",\"hello\",\"puzzles\",\"pianist\",\"unconventional\",\"jumping\",\"sepulchre\"," ascii
    $s18 = "boeotia[regular.shift()](morale, tablecloth, true);tEgugI = \"_F17_\";" fullword ascii
    $s19 = "var award =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".advertisers4();" fullword ascii
    $s20 = "            silent[fluffy]((\"theology\",\"cartoons\",\"G\" + weasel) + (\"instances\",\"requisition\",\"juice\",\"organ\",\"T\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}