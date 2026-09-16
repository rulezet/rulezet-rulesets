rule sig_20160518_c7fdc57ed6b55d0137fb693f5eb75889 {
  meta:
    description = "datamaliciousorder - file 20160518_c7fdc57ed6b55d0137fb693f5eb75889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "814cd6a10415b65e68df66ec8c49df655550d5bad53c53e70356f7ec0b0e6768"

  strings:
    $s1  = "var motherless = [sheath, overthrew,chandelier,  \"\"+\".\"+(\"julia\",\"arbitration\",\"injection\",\"pounce\",\"burdensome\"," ascii
    $s2  = "var motherless = [sheath, overthrew,chandelier,  \"\"+\".\"+(\"julia\",\"arbitration\",\"injection\",\"pounce\",\"burdensome\"," ascii
    $s3  = "illegally = ((\"characteristically\", \"rehearse\", \"marred\", \"immunology\", \"sLpVtdYE\") + \"zjjXpv\").tribute2();" fullword ascii
    $s4  = "sward(\"aHR0cDovLw==\".tribute4()+\"\\u0069\\u006B\\u006F\\u006E\\u0069\\u0063\\u0065\\u006B\\u002E\\u0077\\u007A\"+\"\\u002E\\u" ascii
    $s5  = "holly = holly+ motherless.shift();" fullword ascii
    $s6  = "String.prototype.tribute = function () {" fullword ascii
    $s7  = "var impartiality = motherless.pop().split(\">\");" fullword ascii
    $s8  = "String.prototype.tribute4 = function() {" fullword ascii
    $s9  = "String.prototype.tribute2 = function () {" fullword ascii
    $s10 = "refrigerator = \"b3Blbg==\".tribute4();;" fullword ascii
    $s11 = "weasel = ((\"villa\", \"cardiovascular\", \"heartache\", \"impure\", \"ExMGfnLbjku\") + \"UbwwVQp\").tribute2();" fullword ascii
    $s12 = "fallen, false);" fullword ascii
    $s13 = "dragoman = \"_F2_\";" fullword ascii
    $s14 = "        var exasperate = new mingo(((\"convenience\",\"virtual\",\"smoldering\",\"cosmetic\",\"inclusion\",\"larboard\",\"subsid" ascii
    $s15 = "var reproductive = {" fullword ascii
    $s16 = "var considerations = new mingo(impartiality[0]);" fullword ascii
    $s17 = "function sward(fallen, surely) {" fullword ascii
    $s18 = "var sheath = \"QWopticsN0aXZopticslWE9iaopticsmVjdA=optics=\".tribute4();" fullword ascii
    $s19 = "lengthen = ((\"abler\", \"cigarette\", \"caucasian\", \"floating\", \"pjmqiIu\") + \"jkwtqClwi\").tribute2();" fullword ascii
    $s20 = "sward(\"aHR0cDovLw==\".tribute4()+\"\\u0069\\u006B\\u006F\\u006E\\u0069\\u0063\\u0065\\u006B\\u002E\\u0077\\u007A\"+\"\\u002E\\u" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}