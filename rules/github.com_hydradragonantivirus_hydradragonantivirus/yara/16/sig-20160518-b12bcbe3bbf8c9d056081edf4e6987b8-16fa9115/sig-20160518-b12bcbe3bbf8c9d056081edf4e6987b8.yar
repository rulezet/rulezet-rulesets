rule sig_20160518_b12bcbe3bbf8c9d056081edf4e6987b8 {
  meta:
    description = "datamaliciousorder - file 20160518_b12bcbe3bbf8c9d056081edf4e6987b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa027e0929e3a986b81d42c433c8baaa70c9c28811eadb5c39fa56c68fbcb546"

  strings:
    $s1  = "pineapple = ((\"meuse\", \"prescription\", \"heterogeneous\", \"debtor\", \"pNYghoSKCf\") + \"BjYLYwOfa\").cogent2();" fullword ascii
    $s2  = "        virility[(pineapple + \"o\"+(\"claire\",\"overcome\",\"legend\",\"wonderful\",\"tabooed\",\"seeing\",\"endorsed\",\"beij" ascii
    $s3  = "encroach = ((\"connection\", \"conclusions\", \"finals\", \"counties\", \"sNOSoBpo\") + \"iXePzpMz\").cogent2();" fullword ascii
    $s4  = "colon(\"aHR0cDovLw==\".cogent4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065\"" ascii
    $s5  = "large = large+ dependency.shift();" fullword ascii
    $s6  = "String.prototype.cogent = function () {" fullword ascii
    $s7  = "String.prototype.cogent2 = function () {" fullword ascii
    $s8  = "var booking = dependency.pop().split(\">\");" fullword ascii
    $s9  = "String.prototype.cogent4 = function() {" fullword ascii
    $s10 = "var dependency = [bikini, uphill,creativity,  \"\"+\".\"+(\"inputs\",\"backed\",\"airplane\",\"modem\",\"artificial\",\"votive\"" ascii
    $s11 = "        virility[(pineapple + \"o\"+(\"claire\",\"overcome\",\"legend\",\"wonderful\",\"tabooed\",\"seeing\",\"endorsed\",\"beij" ascii
    $s12 = "var consumer = 0;" fullword ascii
    $s13 = "var attestation = 6/6;" fullword ascii
    $s14 = "colon(\"aHR0cDovLw==\".cogent4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0065\"" ascii
    $s15 = "var chairman = {" fullword ascii
    $s16 = "assassin = \"_F2_\";" fullword ascii
    $s17 = "var dependency = [bikini, uphill,creativity,  \"\"+\".\"+(\"inputs\",\"backed\",\"airplane\",\"modem\",\"artificial\",\"votive\"" ascii
    $s18 = "function colon(ticking, mesopotamia) {" fullword ascii
    $s19 = "demonstrate = \"b3Blbg==\".cogent4();;" fullword ascii
    $s20 = "var uphill =\"RXhwYW5truthfulnesskRW52aXtruthfulnessJvbm1lbnRTdHJtruthfulnesspbmdz\".cogent4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}