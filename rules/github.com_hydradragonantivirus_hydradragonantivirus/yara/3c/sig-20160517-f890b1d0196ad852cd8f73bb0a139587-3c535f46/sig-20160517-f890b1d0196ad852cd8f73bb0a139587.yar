rule sig_20160517_f890b1d0196ad852cd8f73bb0a139587 {
  meta:
    description = "datamaliciousorder - file 20160517_f890b1d0196ad852cd8f73bb0a139587.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f84566dfa20f39c9e44af8c44edad35c2f1b03e51940e420aaa3dcb0654ae909"

  strings:
    $s1  = "climbing(\"aHR0cDovLw==\".levity4()+\"\\u0069\\u006E\\u006E\\u006F\\u0067\\u0065\\u006E\\u0061\\u0070\\u002E\\u0063\"+\"\\u006F" ascii
    $s2  = "var farmers=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".levity4())&&etching[\"c3RhdHVz\".levity4()] +\"\"==\"MjAw\".levity4(" ascii
    $s3  = "var farmers=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".levity4())&&etching[\"c3RhdHVz\".levity4()] +\"\"==\"MjAw\".levity4(" ascii
    $s4  = "weasel = ((\"lindsay\", \"fetid\", \"faraday\", \"feline\", \"EoRmLzxu\") + \"LCikfqzjhJ\").levity2();" fullword ascii
    $s5  = "unwashed = ((\"integration\", \"tenacity\", \"archives\", \"andes\", \"sHBatpeCqY\") + \"myOEtMFE\").levity2();" fullword ascii
    $s6  = "        inversion[(\"horseshoe\",\"andromeda\",\"melon\",\"arbitration\",\"triangle\",\"sidon\",\"democrat\",\"s\")+\"aveT\"+\"o" ascii
    $s7  = "String.prototype.levity = function () {" fullword ascii
    $s8  = "function climbing(unvarying, discrepancy) {" fullword ascii
    $s9  = "        var inversion = new forces(((\"gnarled\",\"huddle\",\"objectives\",\"peach\",\"appertain\",\"illustrations\",\"inspectio" ascii
    $s10 = "        inversion[(\"horseshoe\",\"andromeda\",\"melon\",\"arbitration\",\"triangle\",\"sidon\",\"democrat\",\"s\")+\"aveT\"+\"o" ascii
    $s11 = "climbing(\"aHR0cDovLw==\".levity4()+\"\\u0069\\u006E\\u006E\\u006F\\u0067\\u0065\\u006E\\u0061\\u0070\\u002E\\u0063\"+\"\\u006F" ascii
    $s12 = "String.prototype.levity2 = function () {" fullword ascii
    $s13 = "String.prototype.levity4 = function() {" fullword ascii
    $s14 = "            etching[resulted]((\"technique\",\"attempted\",\"G\" + weasel) + (\"taciturn\",\"provider\",\"mercurial\",\"carrying" ascii
    $s15 = "            etching[resulted]((\"technique\",\"attempted\",\"G\" + weasel) + (\"taciturn\",\"provider\",\"mercurial\",\"carrying" ascii
    $s16 = "        inversion[\"d3JpdGU=\".levity4()](etching[(\"connections\",\"unconvinced\",\"nightlife\",\"global\",\"villager\",\"evenl" ascii
    $s17 = "var utilize =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".levity4();" fullword ascii
    $s18 = "var furlough = {" fullword ascii
    $s19 = "var parenting = [derek, utilize,parallel,  \"\"+\".\"+(\"sluggard\",\"italy\",\"functions\",\"gossip\",\"toner\",\"volume\",\"ci" ascii
    $s20 = "var prate = stamp[parenting.shift()](parenting.shift());" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}