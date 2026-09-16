rule sig_20160519_d44f2b45fb269480461e1db09d0c0e0b {
  meta:
    description = "datamaliciousorder - file 20160519_d44f2b45fb269480461e1db09d0c0e0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9da3f94b1f3e9d2a6ffb29b178e04ac6bff7524fd59dd085568be2196285d9d4"

  strings:
    $s1  = "var brick = [verse, socialist,numbness,  \"\"+\".\"+(\"dearth\",\"cauliflower\",\"deleted\",\"begat\",\"sustainability\",\"buckw" ascii
    $s2  = "corvette = corvette+ brick.shift();" fullword ascii
    $s3  = "weasel = ((\"substratum\", \"george\", \"filled\", \"warped\", \"EySjVJjFeeMF\") + \"jMuvBw\").elimination2();" fullword ascii
    $s4  = "genoese(\"aHR0cDovLw==\".elimination4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F" ascii
    $s5  = "String.prototype.elimination = function () {" fullword ascii
    $s6  = "String.prototype.elimination2 = function () {" fullword ascii
    $s7  = "\"ML\"+(\"politics\",\"dozens\",\"installing\",\"cocktail\",\"stuffed\",\"profanity\",\"elemental\",\"2.\")+\"|M\"+\"LH\"+\"TT\"" ascii
    $s8  = "String.prototype.elimination4 = function() {" fullword ascii
    $s9  = "genoese(\"aHR0cDovLw==\".elimination4()+\"\\u007A\\u0061\\u0072\\u0061\\u0062\\u006F\\u0074\\u0061\\u0074\\u002E\\u0079\\u006F" ascii
    $s10 = "var saint = this[brick.shift()];" fullword ascii
    $s11 = "var verse = \"QWemulationN0aXZemulationlWE9iaemulationmVjdA=emulation=\".elimination4();" fullword ascii
    $s12 = "planner = \"_F2_\";" fullword ascii
    $s13 = "function genoese(senators, superlative) {" fullword ascii
    $s14 = "idyllic[brick.shift()](corvette, roadway, true);" fullword ascii
    $s15 = "var verbs = new saint(lapland[0]);" fullword ascii
    $s16 = "var roadway = 3-2;  " fullword ascii
    $s17 = "var numbness =\"JVemulationRFTVemulationAl\".elimination4();" fullword ascii
    $s18 = "var socialist =\"RXhwYW5emulationkRW52aXemulationJvbm1lbnRTdHJemulationpbmdz\".elimination4();" fullword ascii
    $s19 = "var tinkling = 0;" fullword ascii
    $s20 = "        var detroit = new saint(((\"tagalog\",\"trembl\",\"spray\",\"pennant\",\"jewess\",\"sociable\",\"florida\",\"shaping\"," ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}