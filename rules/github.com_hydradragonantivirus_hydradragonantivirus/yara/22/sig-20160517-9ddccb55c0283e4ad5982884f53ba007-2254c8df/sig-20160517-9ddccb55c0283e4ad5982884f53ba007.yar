rule sig_20160517_9ddccb55c0283e4ad5982884f53ba007 {
  meta:
    description = "datamaliciousorder - file 20160517_9ddccb55c0283e4ad5982884f53ba007.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fba221c4bd13ef542cc7a186e02f72583cac75a2d0120f7ff1522f732883fa6"

  strings:
    $s1  = "patio(\"aHR0cDovLw==\".importune4()+\"\\u006D\\u0075\\u0072\\u0069\\u006E\\u002E\\u006E\\u0065\"+\"\\u0074\\u002F\\u0030\\u0075" ascii
    $s2  = "weasel = ((\"presidency\", \"pinkerton\", \"soliloquy\", \"solutions\", \"EgisKaRvGRA\") + \"fFjjPGCdX\").importune2();" fullword ascii
    $s3  = "String.prototype.importune4 = function() {" fullword ascii
    $s4  = "String.prototype.importune2 = function () {" fullword ascii
    $s5  = "var translation = [endearment, sized,subsidiary,  \"\"+\".\"+(\"hunch\",\"lexmark\",\"sunrise\",\"parameter\",\"indicating\",\"b" ascii
    $s6  = "String.prototype.importune = function () {" fullword ascii
    $s7  = "            eliminated[births]((\"margarita\",\"panther\",\"G\" + weasel) + (\"westerly\",\"rental\",\"headline\",\"bolivia\",\"" ascii
    $s8  = "            eliminated[births]((\"margarita\",\"panther\",\"G\" + weasel) + (\"westerly\",\"rental\",\"headline\",\"bolivia\",\"" ascii
    $s9  = "var squirt = translation.pop().split(\"" fullword ascii
    $s10 = "var endearment = \"QWcycleN0aXZcyclelWE9iacyclemVjdA=cycle=\".importune4();" fullword ascii
    $s11 = "var subsidiary =\"JVcycleRFTVcycleAl\".importune4();" fullword ascii
    $s12 = "var sized =\"RXhwYW5cyclekRW52aXcycleJvbm1lbnRTdHJcyclepbmdz\".importune4();" fullword ascii
    $s13 = "patio(\"aHR0cDovLw==\".importune4()+\"\\u006D\\u0075\\u0072\\u0069\\u006E\\u002E\\u006E\\u0065\"+\"\\u0074\\u002F\\u0030\\u0075" ascii
    $s14 = "\"quarterly\",\"projector\",\"sunset\",\"upholstery\",\"voyeurweb\",\"penury\",\"electric\",\"SEOO\")+\"DB\"+(\"catalog\",\"wher" ascii
    $s15 = "        wireless[(\"involvement\",\"width\",\"ironic\",\"admin\",\"conscription\",\"radius\",\"motherboard\",\"s\")+\"aveT\"+\"o" ascii
    $s16 = "        wireless[(\"involvement\",\"width\",\"ironic\",\"admin\",\"conscription\",\"radius\",\"motherboard\",\"s\")+\"aveT\"+\"o" ascii
    $s17 = "for (var i in workers){graham = graham.replace(i, workers[i]);}" fullword ascii
    $s18 = "var eliminated = new russian(squirt[0]);" fullword ascii
    $s19 = "var silicon = new russian(squirt[1]);" fullword ascii
    $s20 = "silicon[translation.shift()](instructors, impulsive, true);OKrLdRdv = \"_F17_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}