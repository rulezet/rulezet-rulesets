rule sig_20160516_cdd3313e8515cd06467c3578e9011e90 {
  meta:
    description = "datamaliciousorder - file 20160516_cdd3313e8515cd06467c3578e9011e90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b4ed329b69c0b3460adbd14322e45f9b0b2b2fb41cc32d6c929c26825fdea74"

  strings:
    $s1  = "        flying[(olfactory + \"o\"+(\"muscles\",\"starting\",\"masters\",\"launch\",\"communist\",\"comics\",\"chirp\",\"designer" ascii
    $s2  = "        flying[(olfactory + \"o\"+(\"muscles\",\"starting\",\"masters\",\"launch\",\"communist\",\"comics\",\"chirp\",\"designer" ascii
    $s3  = "docility(\"aHR0cDovLw==\".windfall4()+\"\\u0062\\u0065\\u006C\\u0075\\u0078\\u0066\\u0075\\u0072\\u006E\\u0069\\u0074\\u0075\\u0" ascii
    $s4  = "weasel = ((\"potential\", \"trailers\", \"consultant\", \"bilateral\", \"EMjDRpknLw\") + \"MbMhXtsyq\").windfall2();" fullword ascii
    $s5  = "var ninetysix = [arbitration, assistant,photographic,  \"\"+\".\"+(\"implications\",\"activities\",\"release\",\"veracity\",\"re" ascii
    $s6  = "String.prototype.windfall2 = function () {" fullword ascii
    $s7  = "tic\",\"friesland\",\"comfort\",\"penalty\",\"context\",\"modes\",\"andalusia\",\"8i\")+\"tion\").replace(\"0\"+(\"napkin\",\"ex" ascii
    $s8  = "String.prototype.windfall4 = function() {" fullword ascii
    $s9  = "baptismal[ninetysix.shift()](volumes, ports, true);SCzDostqvX = \"_F17_\";" fullword ascii
    $s10 = "String.prototype.windfall = function () {" fullword ascii
    $s11 = "orbit = \"_F2_\";" fullword ascii
    $s12 = "var hauteur = 0;" fullword ascii
    $s13 = "docility(\"aHR0cDovLw==\".windfall4()+\"\\u0062\\u0065\\u006C\\u0075\\u0078\\u0066\\u0075\\u0072\\u006E\\u0069\\u0074\\u0075\\u0" ascii
    $s14 = "var penknife = {" fullword ascii
    $s15 = "var photographic =\"JVRFTVAl\".windfall4();" fullword ascii
    $s16 = "function docility(milfhunter, tentative) {" fullword ascii
    $s17 = "var assistant =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".windfall4();" fullword ascii
    $s18 = "var baptismal = new holmes(richie[1]);" fullword ascii
    $s19 = "var holmes = this[ninetysix.shift()];" fullword ascii
    $s20 = "var arbitration = \"QWN0aXZlWE9iamVjdA==\".windfall4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}