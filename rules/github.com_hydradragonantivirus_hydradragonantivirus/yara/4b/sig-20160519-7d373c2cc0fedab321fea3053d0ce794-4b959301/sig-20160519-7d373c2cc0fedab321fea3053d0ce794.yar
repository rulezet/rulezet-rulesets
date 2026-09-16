rule sig_20160519_7d373c2cc0fedab321fea3053d0ce794 {
  meta:
    description = "datamaliciousorder - file 20160519_7d373c2cc0fedab321fea3053d0ce794.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b04f97d27ba41e517b0fc4fa06dbb60b6f10a10c11a620164518d3626896409"

  strings:
    $s1  = "var conversely = [sanguinary, columnists,blackberry,  \"\"+\".\"+(\"pyramidal\",\"occurring\",\"phosphorus\",\"unwieldy\",\"civi" ascii
    $s2  = "var headway = conversely.pop().split(\">\");" fullword ascii
    $s3  = "weasel = ((\"clarity\", \"compile\", \"moving\", \"inkling\", \"ECltbIdWyMi\") + \"MAadfyUnF\").ambrosia2();" fullword ascii
    $s4  = "var trader=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".ambrosia4())&&arbiter[\"c3RhdHVz\".ambrosia4()] +\"\"==\"MjAw\".ambro" ascii
    $s5  = "var trader=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".ambrosia4())&&arbiter[\"c3RhdHVz\".ambrosia4()] +\"\"==\"MjAw\".ambro" ascii
    $s6  = "vicissitude(\"aHR0cDovLw==\".ambrosia4()+\"\\u006D\\u0061\\u0072\\u0070\\u0065\\u006E\\u002E\\u0063\"+\"\\u0061\\u002F\\u0065\\u" ascii
    $s7  = "String.prototype.ambrosia4 = function() {" fullword ascii
    $s8  = "var importantly = 0;" fullword ascii
    $s9  = "String.prototype.ambrosia = function () {" fullword ascii
    $s10 = "String.prototype.ambrosia2 = function () {" fullword ascii
    $s11 = "        sprightly[(station + \"o\"+(\"awesome\",\"bitch\",\"fakir\",\"approve\",\"aberrations\",\"phoenician\",\"burman\",\"peda" ascii
    $s12 = "var galvanometer = new calendars(headway[1]);" fullword ascii
    $s13 = "var arbiter = new calendars(headway[0]);" fullword ascii
    $s14 = "destroyer = \"b3Blbg==\".ambrosia4();;" fullword ascii
    $s15 = "perplexing = \"_F2_\";" fullword ascii
    $s16 = "function vicissitude(bulwark, flirt) {" fullword ascii
    $s17 = "galvanometer[conversely.shift()](greenland, gardens, true);" fullword ascii
    $s18 = "var conversely = [sanguinary, columnists,blackberry,  \"\"+\".\"+(\"pyramidal\",\"occurring\",\"phosphorus\",\"unwieldy\",\"civi" ascii
    $s19 = "var sanguinary = \"QWrudderN0aXZrudderlWE9iaruddermVjdA=rudder=\".ambrosia4();" fullword ascii
    $s20 = "var blackberry =\"JVrudderRFTVrudderAl\".ambrosia4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}