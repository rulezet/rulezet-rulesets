rule sig_20160519_79bbed1e8c942facae5436b44f80ccda {
  meta:
    description = "datamaliciousorder - file 20160519_79bbed1e8c942facae5436b44f80ccda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a597b5aeba10e639378ba046019e30c79d40b304c068eba6ac2af7b7f2ef779a"

  strings:
    $x1  = "var worry = [catholic, insidiously,bruges,  \"\"+\".\"+(\"keyboards\",\"downloads\",\"equestrian\",\"leathery\",\"animus\",\"che" ascii
    $s2  = "var worry = [catholic, insidiously,bruges,  \"\"+\".\"+(\"keyboards\",\"downloads\",\"equestrian\",\"leathery\",\"animus\",\"che" ascii
    $s3  = "var pondering=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".investments4())&&abbreviation[\"c3RhdHVz\".investments4()] +\"\"==" ascii
    $s4  = "var pondering=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".investments4())&&abbreviation[\"c3RhdHVz\".investments4()] +\"\"==" ascii
    $s5  = "\",\"invest\",\"attention\",\"turpentine\",\"soliloquy\",\"analysis\",\"whomsoever\",\"P>\")+\"WU\"+(\"recognizable\",\"epilogue" ascii
    $s6  = "spasm = spasm+ worry.shift();" fullword ascii
    $s7  = "rotary(\"aHR0cDovLw==\".investments4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u00" ascii
    $s8  = "weasel = ((\"knell\", \"fallacy\", \"tardily\", \"property\", \"ElrfORfEfSLx\") + \"ShPaOVkkEVL\").investments2();" fullword ascii
    $s9  = "auditorium = ((\"boutique\", \"closest\", \"guest\", \"vitals\", \"pDzOWfjA\") + \"crYzrB\").investments2();" fullword ascii
    $s10 = "String.prototype.investments4 = function() {" fullword ascii
    $s11 = "String.prototype.investments = function () {" fullword ascii
    $s12 = "var unfavorable = worry.pop().split(\">\");" fullword ascii
    $s13 = "String.prototype.investments2 = function () {" fullword ascii
    $s14 = "    abbreviation[shares + (\"newspapers\",\"talmud\",\"end\")]();" fullword ascii
    $s15 = "\"+\"ML\"+(\"interpreted\",\"checked\",\"tahiti\",\"liable\",\"consistently\",\"jackal\",\"unsound\",\"2.\")+\"|M\"+\"LH\"+\"TT" ascii
    $s16 = "for (var i in correction){smaller = smaller.replace(i, correction[i]);}" fullword ascii
    $s17 = "var insidiously =\"RXhwYW5huntingtonkRW52aXhuntingtonJvbm1lbnRTdHJhuntingtonpbmdz\".investments4();" fullword ascii
    $s18 = "var correction = {" fullword ascii
    $s19 = "var exhalation = depleted[worry.shift()](worry.shift());" fullword ascii
    $s20 = "var abbreviation = new forelock(unfavorable[0]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}