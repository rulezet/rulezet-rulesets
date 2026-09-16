rule sig_20160517_7a320c8ddf968151e28472668de614c4 {
  meta:
    description = "datamaliciousorder - file 20160517_7a320c8ddf968151e28472668de614c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab8a631f96b11a961b6f173a0dc772678a0f449f5a55bf79cd3a70fc660946f8"

  strings:
    $s1  = "weasel = ((\"component\", \"condition\", \"lashing\", \"analyses\", \"ElHrJArJiFfJ\") + \"BsqzOSzia\").thoughts2();" fullword ascii
    $s2  = "dissolving = ((\"alias\", \"passes\", \"elimination\", \"conflagration\", \"shqOauIJYn\") + \"UjtWDRR\").thoughts2();" fullword ascii
    $s3  = "var sioux=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".thoughts4())&&encumbrance[\"c3RhdHVz\".thoughts4()] +\"\"==\"MjAw\".th" ascii
    $s4  = "var sioux=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".thoughts4())&&encumbrance[\"c3RhdHVz\".thoughts4()] +\"\"==\"MjAw\".th" ascii
    $s5  = "var victim = prominent[tough.shift()](tough.shift());" fullword ascii
    $s6  = "plastic(\"aHR0cDovLw==\".thoughts4()+\"\\u0061\\u0072\\u0061\\u0062\\u0069\\u0061\\u006E\\u002D\\u0073\\u0074\\u0061\\u0072\\u00" ascii
    $s7  = "String.prototype.thoughts4 = function() {" fullword ascii
    $s8  = "animates\",\"sulphide\",\"digital\",\"reads\",\"pretension\",\"08\"), dissolving)] = 0;" fullword ascii
    $s9  = "        alliance[(carolina + \"o\"+(\"scheduling\",\"buzzing\",\"lemonade\",\"academies\",\"amanuensis\",\"assignment\",\"direct" ascii
    $s10 = "            encumbrance[assessment]((\"bulkhead\",\"squat\",\"G\" + weasel) + (\"obviate\",\"obloquy\",\"dosage\",\"locally\",\"" ascii
    $s11 = "String.prototype.thoughts = function () {" fullword ascii
    $s12 = "            encumbrance[assessment]((\"bulkhead\",\"squat\",\"G\" + weasel) + (\"obviate\",\"obloquy\",\"dosage\",\"locally\",\"" ascii
    $s13 = "String.prototype.thoughts2 = function () {" fullword ascii
    $s14 = "var tough = [eagles, serve,fragile,  \"\"+\".\"+(\"reload\",\"voted\",\"medicine\",\"assailant\",\"corresponds\",\"prostate\",\"" ascii
    $s15 = "n, false);" fullword ascii
    $s16 = "var fragile =\"JVRFTVAl\".thoughts4();" fullword ascii
    $s17 = "guitar\",\"mitsubishi\",\"solutions\",\"morocco\",\"unofficial\",\"notes\",\"briar\",\"monosyllable\",\"SEOO\")+\"DB\"+(\"instru" ascii
    $s18 = "for (var i in progress){deadened = deadened.replace(i, progress[i]);}" fullword ascii
    $s19 = "flashlight = \"_F2_\";" fullword ascii
    $s20 = "var tough = [eagles, serve,fragile,  \"\"+\".\"+(\"reload\",\"voted\",\"medicine\",\"assailant\",\"corresponds\",\"prostate\",\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}