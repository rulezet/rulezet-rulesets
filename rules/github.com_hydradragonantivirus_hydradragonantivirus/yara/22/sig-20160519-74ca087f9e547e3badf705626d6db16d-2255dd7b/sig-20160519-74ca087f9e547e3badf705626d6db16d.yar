rule sig_20160519_74ca087f9e547e3badf705626d6db16d {
  meta:
    description = "datamaliciousorder - file 20160519_74ca087f9e547e3badf705626d6db16d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69461549378d8edcfe70967ec9ff150b1ac1446ae203aec98cf304b76c77dd4f"

  strings:
    $s1  = "        var beehive = new salve(((\"passageway\",\"administrators\",\"inputs\",\"installation\",\"execration\",\"mitigation\",\"" ascii
    $s2  = "        var beehive = new salve(((\"passageway\",\"administrators\",\"inputs\",\"installation\",\"execration\",\"mitigation\",\"" ascii
    $s3  = "var ravenously=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".standstill4())&&archipelago[\"c3RhdHVz\".standstill4()] +\"\"==\"" ascii
    $s4  = "var dazzle = [literati, saving,bearable,  \"\"+\".\"+(\"disposal\",\"whiten\",\"functionality\",\"treasures\",\"thereabout\",\"s" ascii
    $s5  = "var ravenously=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".standstill4())&&archipelago[\"c3RhdHVz\".standstill4()] +\"\"==\"" ascii
    $s6  = "function wellfed(extirpation, nugget) {" fullword ascii
    $s7  = "        var spider = skill + \"/\" + nugget ;" fullword ascii
    $s8  = "spider = spider+ dazzle.shift();" fullword ascii
    $s9  = "weasel = ((\"forest\", \"sieve\", \"saint\", \"cheese\", \"EHHDiDyyBoP\") + \"oBtFXyKa\").standstill2();" fullword ascii
    $s10 = "godless = ((\"avenue\", \"stuart\", \"abstained\", \"jubilee\", \"pJrUicrCMl\") + \"JWwqQBGDp\").standstill2();" fullword ascii
    $s11 = "String.prototype.standstill4 = function() {" fullword ascii
    $s12 = "String.prototype.standstill = function () {" fullword ascii
    $s13 = "String.prototype.standstill2 = function () {" fullword ascii
    $s14 = "var literati = \"QWrobinN0aXZrobinlWE9iarobinmVjdA=robin=\".standstill4();" fullword ascii
    $s15 = "var bearable =\"JVrobinRFTVrobinAl\".standstill4();" fullword ascii
    $s16 = "var heaven = dazzle.pop().split(\">\");" fullword ascii
    $s17 = "var saving =\"RXhwYW5robinkRW52aXrobinJvbm1lbnRTdHJrobinpbmdz\".standstill4();" fullword ascii
    $s18 = "var salve = this[dazzle.shift()];" fullword ascii
    $s19 = "costume[dazzle.shift()](spider, allan, true);" fullword ascii
    $s20 = "unitarian = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}