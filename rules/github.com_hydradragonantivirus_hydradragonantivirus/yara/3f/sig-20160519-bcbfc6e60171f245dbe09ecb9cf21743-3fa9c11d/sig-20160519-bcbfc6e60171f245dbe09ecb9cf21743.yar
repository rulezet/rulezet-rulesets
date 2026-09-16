rule sig_20160519_bcbfc6e60171f245dbe09ecb9cf21743 {
  meta:
    description = "datamaliciousorder - file 20160519_bcbfc6e60171f245dbe09ecb9cf21743.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cec1fcfc8e83a988dca35f21593a5ae42c1406957552c1e9127e85ee593e256"

  strings:
    $s1  = "darkness = ((\"pommel\", \"desirable\", \"nauseous\", \"lancet\", \"pCiAhrvU\") + \"otHHpE\").opening2();" fullword ascii
    $s2  = "var client = [sententious, indonesia,erudite,  \"\"+\".\"+(\"seaport\",\"vestibule\",\"differentiation\",\"adrian\",\"pianist\"," ascii
    $s3  = "var sheets=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".opening4())&&pantheism[\"c3RhdHVz\".opening4()] +\"\"==\"MjAw\".openi" ascii
    $s4  = "var sheets=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".opening4())&&pantheism[\"c3RhdHVz\".opening4()] +\"\"==\"MjAw\".openi" ascii
    $s5  = "reborn = reborn+ client.shift();" fullword ascii
    $s6  = "weasel = ((\"metropolitan\", \"hindrance\", \"tantamount\", \"subsides\", \"ElHWPUgurhx\") + \"Djtlrkpo\").opening2();" fullword ascii
    $s7  = "gravity(\"aHR0cDovLw==\".opening4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F\\u006" ascii
    $s8  = "String.prototype.opening2 = function () {" fullword ascii
    $s9  = "String.prototype.opening4 = function() {" fullword ascii
    $s10 = "        terms[(darkness + \"o\"+(\"canned\",\"schoolgirl\",\"versed\",\"voluntary\",\"bowled\",\"liveliness\",\"ponder\",\"films" ascii
    $s11 = "String.prototype.opening = function () {" fullword ascii
    $s12 = "var erudite =\"JVharmedRFTVharmedAl\".opening4();" fullword ascii
    $s13 = "gravity(\"aHR0cDovLw==\".opening4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F\\u006" ascii
    $s14 = "var reserved = {" fullword ascii
    $s15 = "        terms[(darkness + \"o\"+(\"canned\",\"schoolgirl\",\"versed\",\"voluntary\",\"bowled\",\"liveliness\",\"ponder\",\"films" ascii
    $s16 = "congestion = \"b3Blbg==\".opening4();" fullword ascii
    $s17 = "var precipitation = 0;" fullword ascii
    $s18 = "flatterer = \"_F2_\";" fullword ascii
    $s19 = "var wired = 3-2;  " fullword ascii
    $s20 = "  statuary = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}