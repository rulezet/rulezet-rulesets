rule sig_20160516_1227020f2cf50285de595c35eba6894f {
  meta:
    description = "datamaliciousorder - file 20160516_1227020f2cf50285de595c35eba6894f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c0da4a79fda2641bf271e0ce40210677fc715c5e04aed836f5902644d3d0901"

  strings:
    $s1  = "var invidious = [graduated, limousine,piers,  \"\"+\".\"+(\"subsequent\",\"indite\",\"atrocity\",\"poisoning\",\"korea\",\"tutor" ascii
    $s2  = "var invidious = [graduated, limousine,piers,  \"\"+\".\"+(\"subsequent\",\"indite\",\"atrocity\",\"poisoning\",\"korea\",\"tutor" ascii
    $s3  = "var arabia=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".realist4())&&fixtures[\"c3RhdHVz\".realist4()] +\"\"==\"MjAw\".realis" ascii
    $s4  = "var theology = 0;" fullword ascii
    $s5  = "brewery = ((\"annul\", \"mither\", \"niggard\", \"sculpture\", \"pBSPVvTHI\") + \"QKCncBfDrTT\").realist2();" fullword ascii
    $s6  = "weasel = ((\"achieving\", \"opinion\", \"record\", \"supplements\", \"EJNbmhuNyom\") + \"gGsAiABNj\").realist2();" fullword ascii
    $s7  = "String.prototype.realist4 = function() {" fullword ascii
    $s8  = "var dietary = invidious.pop().split(\"" fullword ascii
    $s9  = "String.prototype.realist = function () {" fullword ascii
    $s10 = "String.prototype.realist2 = function () {" fullword ascii
    $s11 = "            fixtures[really]((\"cleansing\",\"occupations\",\"G\" + weasel) + (\"temperamental\",\"harris\",\"flowers\",\"podcas" ascii
    $s12 = "        imparting[(brewery + \"o\"+(\"engaging\",\"monetary\",\"undercurrent\",\"crunch\",\"mediterranean\",\"transform\",\"acdb" ascii
    $s13 = "            fixtures[really]((\"cleansing\",\"occupations\",\"G\" + weasel) + (\"temperamental\",\"harris\",\"flowers\",\"podcas" ascii
    $s14 = "        imparting[(brewery + \"o\"+(\"engaging\",\"monetary\",\"undercurrent\",\"crunch\",\"mediterranean\",\"transform\",\"acdb" ascii
    $s15 = "erCase())](theology, solder);" fullword ascii
    $s16 = "var cycling = {" fullword ascii
    $s17 = "var solder = 6/6;" fullword ascii
    $s18 = "var scientist = adware[invidious.shift()](invidious.shift());" fullword ascii
    $s19 = "adware[invidious.shift()](eightythree, solder, true);XtFxUNz = \"_F17_\";" fullword ascii
    $s20 = "var automobiles = this[invidious.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}