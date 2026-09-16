rule sig_20160517_0306ae4b691d64cf60544a557e071b13 {
  meta:
    description = "datamaliciousorder - file 20160517_0306ae4b691d64cf60544a557e071b13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "575318591764358416c30f3f689c2927e585e1f94b8207fd4fb041c0f0867348"

  strings:
    $s1  = "weasel = ((\"recover\", \"outcome\", \"getting\", \"crystalline\", \"ExgVxeItS\") + \"PzhybvWlos\").locally2();" fullword ascii
    $s2  = "var steel = [balloon, lending,reappearance,  \"\"+\".\"+(\"ramble\",\"outdoor\",\"bleaching\",\"divan\",\"matrimony\",\"beautifu" ascii
    $s3  = "naming = ((\"certificate\", \"introduction\", \"yacht\", \"masthead\", \"prkGJTfJBPy\") + \"kOogvlinz\").locally2();" fullword ascii
    $s4  = "var lombardy=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".locally4())&&trainer[\"c3RhdHVz\".locally4()] +\"\"==\"MjAw\".local" ascii
    $s5  = "var lombardy=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".locally4())&&trainer[\"c3RhdHVz\".locally4()] +\"\"==\"MjAw\".local" ascii
    $s6  = "presage = presage+ steel.shift();" fullword ascii
    $s7  = "ey\",\"s\")+\"ubRt\"+(\"occurrence\",\"brick\",\"porridge\",\"snore\",\"normally\",\"abashed\",\"jesus\",\"ri\")+\"ng\").replace" ascii
    $s8  = "primate(\"aHR0cDovLw==\".locally4()+\"\\u006A\\u0061\\u0073\\u006F\\u006E\\u0063\\u006F\\u0072\\u006F\\u0079\\u002E\\u0063\"+\"" ascii
    $s9  = "            trainer[jogging]((\"holder\",\"strut\",\"G\" + weasel) + (\"competitions\",\"missive\",\"sense\",\"colourless\",\"T" ascii
    $s10 = "        tracker[(naming + \"o\"+(\"begun\",\"missing\",\"althea\",\"migrate\",\"adder\",\"unerring\",\"huntington\",\"adequately" ascii
    $s11 = "String.prototype.locally4 = function() {" fullword ascii
    $s12 = "String.prototype.locally = function () {" fullword ascii
    $s13 = "            trainer[jogging]((\"holder\",\"strut\",\"G\" + weasel) + (\"competitions\",\"missive\",\"sense\",\"colourless\",\"T" ascii
    $s14 = "String.prototype.locally2 = function () {" fullword ascii
    $s15 = "var effigy = 0;" fullword ascii
    $s16 = "var trainer = new experiments(rejected[0]);" fullword ascii
    $s17 = "var demean = siemens[steel.shift()](steel.shift());" fullword ascii
    $s18 = "var upheaval = 6/6;" fullword ascii
    $s19 = "var unwashed = {" fullword ascii
    $s20 = "converter = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}