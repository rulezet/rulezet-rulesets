rule sig_20160516_da0d0dac920441479c5b912a88a30478 {
  meta:
    description = "datamaliciousorder - file 20160516_da0d0dac920441479c5b912a88a30478.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc5be9b506ac8d4de04ef6f221b9e04647dc942041a6811981181d2b00af0471"

  strings:
    $s1  = "            heard[docility]((\"naturally\",\"mucous\",\"G\" + weasel) + (\"pipes\",\"conventional\",\"discover\",\"electro\",\"T" ascii
    $s2  = "            heard[docility]((\"naturally\",\"mucous\",\"G\" + weasel) + (\"pipes\",\"conventional\",\"discover\",\"electro\",\"T" ascii
    $s3  = "weasel = ((\"charge\", \"disability\", \"responses\", \"smoky\", \"EcodoGEKF\") + \"LBMboh\").measurement2();" fullword ascii
    $s4  = "theoretic(\"aHR0cDovLw==\".measurement4()+\"\\u0077\\u0077\\u0077\\u002E\\u0061\\u0070\\u0070\\u0061\\u0072\\u0065\\u006C\\u0062" ascii
    $s5  = "String.prototype.measurement4 = function() {" fullword ascii
    $s6  = "var involvement = ludwig.pop().split(\"" fullword ascii
    $s7  = "\")+\"WU\"+(\"persistent\",\"autocracy\",\"snowball\",\"branches\",\"kidney\",\"creamy\",\"compression\",\"cr\")+(\"amassed\",\"" ascii
    $s8  = "String.prototype.measurement = function () {" fullword ascii
    $s9  = "String.prototype.measurement2 = function () {" fullword ascii
    $s10 = "var ludwig = [expatiate, immutable,television,  \"\"+\".\"+(\"pasty\",\"disposal\",\"fares\",\"injured\",\"enemies\",\"catherine" ascii
    $s11 = "var expatiate = \"QWN0aXZlWE9iamVjdA==\".measurement4();" fullword ascii
    $s12 = "var closing = this[ludwig.shift()];" fullword ascii
    $s13 = "var television =\"JVRFTVAl\".measurement4();" fullword ascii
    $s14 = "var immutable =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".measurement4();" fullword ascii
    $s15 = "function theoretic(spontaneity, amanda) {" fullword ascii
    $s16 = "var residue = 0;" fullword ascii
    $s17 = "  charter = [];" fullword ascii
    $s18 = "theoretic(\"aHR0cDovLw==\".measurement4()+\"\\u0077\\u0077\\u0077\\u002E\\u0061\\u0070\\u0070\\u0061\\u0072\\u0065\\u006C\\u0062" ascii
    $s19 = "        plumber[(\"detector\",\"sausage\",\"franc\",\"anatomy\",\"eightytwo\",\"foreword\",\"other\",\"w\")+\"ri\"+\"te\"](heard" ascii
    $s20 = "for (var i in attribute){archives = archives.replace(i, attribute[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}