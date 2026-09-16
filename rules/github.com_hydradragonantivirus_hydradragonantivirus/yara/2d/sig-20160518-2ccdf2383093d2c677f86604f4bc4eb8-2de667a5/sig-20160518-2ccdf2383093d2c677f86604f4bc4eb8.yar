rule sig_20160518_2ccdf2383093d2c677f86604f4bc4eb8 {
  meta:
    description = "datamaliciousorder - file 20160518_2ccdf2383093d2c677f86604f4bc4eb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37cfd756bc9ae8004192c90ec72aad7fb29641db5057593069a26637b780ae8c"

  strings:
    $s1  = "weasel = ((\"adoring\", \"disgorge\", \"forget\", \"presenting\", \"EPvzzbLKyUWJ\") + \"MmJsiSKluH\").burrow2();" fullword ascii
    $s2  = "var puzzles=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".burrow4())&&germanic[\"c3RhdHVz\".burrow4()] +\"\"==\"MjAw\".burrow4" ascii
    $s3  = "var puzzles=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".burrow4())&&germanic[\"c3RhdHVz\".burrow4()] +\"\"==\"MjAw\".burrow4" ascii
    $s4  = "var academics = [housewares, abstracts,archangel,  \"\"+\".\"+(\"tally\",\"spire\",\"reproductive\",\"ariel\",\"whomsoever\",\"n" ascii
    $s5  = "for (var i in rewritten){astrology = astrology.replace(i, rewritten[i]);}" fullword ascii
    $s6  = "astrology = this;" fullword ascii
    $s7  = "String.prototype.burrow4 = function() {" fullword ascii
    $s8  = "String.prototype.burrow = function () {" fullword ascii
    $s9  = "portend = portend+ academics.shift();" fullword ascii
    $s10 = "String.prototype.burrow2 = function () {" fullword ascii
    $s11 = "        bravado[(samaritan + \"o\"+(\"bermuda\",\"poverty\",\"parlance\",\"comply\",\"clouds\",\"controlled\",\"odyssey\",\"moni" ascii
    $s12 = "        var portend = meaning + \"/\" + fount ;" fullword ascii
    $s13 = "        bravado[(samaritan + \"o\"+(\"bermuda\",\"poverty\",\"parlance\",\"comply\",\"clouds\",\"controlled\",\"odyssey\",\"moni" ascii
    $s14 = "chist\",\"announcements\",\"womanish\",\"putty\",\"metabolism\",\"mutation\",\"P>\")+\"WU\"+(\"homeland\",\"hollywood\",\"makesh" ascii
    $s15 = "function redundant(ariel, fount) {" fullword ascii
    $s16 = "  convalescent = [];" fullword ascii
    $s17 = "var housewares = \"QWessayistN0aXZessayistlWE9iaessayistmVjdA=essayist=\".burrow4();" fullword ascii
    $s18 = "var redound = 0;" fullword ascii
    $s19 = "redundant(\"aHR0cDovLw==\".burrow4()+\"\\u0072\\u006F\\u0074\\u0073\\u0069\\u006E\\u006F\\u006C\\u0069\\u002E\"+\"\\u0072\\u006F" ascii
    $s20 = "    return astrology;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}