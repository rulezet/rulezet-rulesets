rule sig_20160518_540eb95a35ed46cec4c282c5cd6194f9 {
  meta:
    description = "datamaliciousorder - file 20160518_540eb95a35ed46cec4c282c5cd6194f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e186c5fa4bdbd85d2efe09472fdfc12e531e573b131633dd3bce240b41998f99"

  strings:
    $s1  = "var waver = [apparel, canonical,wilkinson,  \"\"+\".\"+(\"colourless\",\"provost\",\"hilarious\",\"covet\",\"lunch\",\"unrequite" ascii
    $s2  = "var physique=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".chancellor4())&&tasteless[\"c3RhdHVz\".chancellor4()] +\"\"==\"MjAw" ascii
    $s3  = "var physique=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".chancellor4())&&tasteless[\"c3RhdHVz\".chancellor4()] +\"\"==\"MjAw" ascii
    $s4  = "ought(\"aHR0cDovLw==\".chancellor4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0072\\u0069\\u0061\\u0072\\u0068\\u0075\\u0072\\u00" ascii
    $s5  = "weasel = ((\"hired\", \"inputs\", \"pants\", \"afflicts\", \"EWqJNThgd\") + \"hMcvovB\").chancellor2();" fullword ascii
    $s6  = "String.prototype.chancellor = function () {" fullword ascii
    $s7  = "var southeastern = waver.pop().split(\">\");" fullword ascii
    $s8  = "String.prototype.chancellor4 = function() {" fullword ascii
    $s9  = "canto = ((\"medline\", \"unconnected\", \"deeprooted\", \"nationally\", \"pfWINFz\") + \"EWHhxA\").chancellor2();" fullword ascii
    $s10 = "String.prototype.chancellor2 = function () {" fullword ascii
    $s11 = "for (var i in nightmare){aryan = aryan.replace(i, nightmare[i]);}" fullword ascii
    $s12 = "var novice = offices[waver.shift()](waver.shift());" fullword ascii
    $s13 = "ought(\"aHR0cDovLw==\".chancellor4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0072\\u0069\\u0061\\u0072\\u0068\\u0075\\u0072\\u00" ascii
    $s14 = "var offices = new firms(southeastern[1]);" fullword ascii
    $s15 = "var rarity = 0;" fullword ascii
    $s16 = "var apparel = \"QWpierreN0aXZpierrelWE9iapierremVjdA=pierre=\".chancellor4();" fullword ascii
    $s17 = "var firms = this[waver.shift()];" fullword ascii
    $s18 = "var nightmare = {" fullword ascii
    $s19 = "var tasteless = new firms(southeastern[0]);" fullword ascii
    $s20 = "offices[waver.shift()](limousines, serenade, true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}