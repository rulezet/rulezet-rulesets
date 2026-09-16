rule sig_20160518_ad9712d7e51ebc5629721f0bc0a45cdf {
  meta:
    description = "datamaliciousorder - file 20160518_ad9712d7e51ebc5629721f0bc0a45cdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fd462bb07a1eaa6a13168ee1c2f4b79cf1969702a5c10203d1254caca49171d"

  strings:
    $s1  = "var leguminous = [produced, administrative,begin,  \"\"+\".\"+(\"norwegian\",\"winds\",\"amethyst\",\"folders\",\"algiers\",\"qu" ascii
    $s2  = "        statistics[(pride + \"o\"+(\"gainsay\",\"sticky\",\"bianca\",\"bramble\",\"darrell\",\"woods\",\"embassy\",\"freeze\",\"" ascii
    $s3  = "var festivity=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sunflower4())&&maddening[\"c3RhdHVz\".sunflower4()] +\"\"==\"MjAw" ascii
    $s4  = "var festivity=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sunflower4())&&maddening[\"c3RhdHVz\".sunflower4()] +\"\"==\"MjAw" ascii
    $s5  = "ace\",\"eyelid\",\"consolidate\",\"tandem\",\"08\"), maple)] = 0;" fullword ascii
    $s6  = "pride = ((\"brainless\", \"wallet\", \"hierarchy\", \"lucky\", \"pDKGBqfQbpLU\") + \"tQXWczBk\").sunflower2();" fullword ascii
    $s7  = "embodiment = embodiment+ leguminous.shift();" fullword ascii
    $s8  = "maple = ((\"foreboding\", \"cossack\", \"airlines\", \"hearings\", \"swOcdQqKI\") + \"wfOMoofTaJ\").sunflower2();" fullword ascii
    $s9  = "weasel = ((\"blocking\", \"gruff\", \"officially\", \"owner\", \"EsDpPCF\") + \"JRizRpFVL\").sunflower2();" fullword ascii
    $s10 = "String.prototype.sunflower4 = function() {" fullword ascii
    $s11 = "String.prototype.sunflower2 = function () {" fullword ascii
    $s12 = "String.prototype.sunflower = function () {" fullword ascii
    $s13 = "        var statistics = new adaptor(((\"shooting\",\"geology\",\"ratings\",\"mammon\",\"vendors\",\"dynamic\",\"himalayas\",\"d" ascii
    $s14 = "sonorous = \"_F2_\";" fullword ascii
    $s15 = "var produced = \"QWeliteN0aXZelitelWE9iaelitemVjdA=elite=\".sunflower4();" fullword ascii
    $s16 = "var extravagantly = {" fullword ascii
    $s17 = "var laggard = 6/6;" fullword ascii
    $s18 = "var maddening = new adaptor(influenced[0]);" fullword ascii
    $s19 = "var administrative =\"RXhwYW5elitekRW52aXeliteJvbm1lbnRTdHJelitepbmdz\".sunflower4();" fullword ascii
    $s20 = "for (var i in extravagantly){assignments = assignments.replace(i, extravagantly[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}