rule sig_20160517_1acea7544ae5525b3615277bb6bde3a0 {
  meta:
    description = "datamaliciousorder - file 20160517_1acea7544ae5525b3615277bb6bde3a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5049015a839a2230bb01694a45fd85a6360b2d09a680587b9479fae4e27225fa"

  strings:
    $s1  = ",\"favors\",\"s\")+\"ubRt\"+(\"cronies\",\"secede\",\"holier\",\"sticks\",\"flier\",\"clark\",\"processing\",\"ri\")+\"ng\").rep" ascii
    $s2  = "convergence = ((\"incredible\", \"logistics\", \"natural\", \"irreligious\", \"srNnwvmcMIJ\") + \"RWEmGTDMie\").island2();" fullword ascii
    $s3  = "weasel = ((\"clothes\", \"strongly\", \"mission\", \"portland\", \"ExDfLcBEbct\") + \"zceYkKbgq\").island2();" fullword ascii
    $s4  = "var scripting=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".island4())&&printers[\"c3RhdHVz\".island4()] +\"\"==\"MjAw\".islan" ascii
    $s5  = "var selfmade = [coordination, freeze,crevasse,  \"\"+\".\"+(\"hundreds\",\"cayman\",\"populations\",\"headset\",\"sumatra\",\"be" ascii
    $s6  = "epitome = epitome+ selfmade.shift();" fullword ascii
    $s7  = "aesthetics(\"aHR0cDovLw==\".island4()+\"\\u0065\\u0063\\u006F\\u006D\\u0075\\u0073\\u0065\\u0065\\u0064\\u0065\\u006C\\u0061\\u0" ascii
    $s8  = "child = ((\"trumpery\", \"breeder\", \"advertise\", \"baseball\", \"psSHhHDrAl\") + \"drpjyFPC\").island2();" fullword ascii
    $s9  = "ffuse\",\"collection\",\"commercial\",\"aspen\",\"08\"), convergence)] = 0;" fullword ascii
    $s10 = "String.prototype.island4 = function() {" fullword ascii
    $s11 = "String.prototype.island2 = function () {" fullword ascii
    $s12 = "String.prototype.island = function () {" fullword ascii
    $s13 = "keyhole = \"_F2_\";" fullword ascii
    $s14 = "    digression.greatest = digression.invisibly[((\"contributors\",\"inopportune\",\"sammy\",\"limousine\",\"grove\",\"greenland" ascii
    $s15 = "var selfmade = [coordination, freeze,crevasse,  \"\"+\".\"+(\"hundreds\",\"cayman\",\"populations\",\"headset\",\"sumatra\",\"be" ascii
    $s16 = "e, false);" fullword ascii
    $s17 = "var cowboy = {" fullword ascii
    $s18 = "var pivot = 0;" fullword ascii
    $s19 = "for (var i in cowboy){narcotic = narcotic.replace(i, cowboy[i]);}" fullword ascii
    $s20 = "var politic = this[selfmade.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}