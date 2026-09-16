rule sig_20160301_7248115795b8510b49d64b5cb85efc81 {
  meta:
    description = "datamaliciousorder - file 20160301_7248115795b8510b49d64b5cb85efc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ab20817ef9728e9bab299c47700aeaf6f40dc58f49500ef11c38bed46c1faff"

  strings:
    $s1 = "trilogyCylinder = totalBarrel[(\"d\" + \"\\u0065l\" + \"t\\u0061\", \"\\u0065x\" + \"\\u0074\\u0072\" + \"a\\u0063\\u0074\", \"t" ascii
    $s2 = "while(trilogyCylinder[(\"re\" + \"\\u0061dy\\u0073\" + \"\\u0074a\" + \"\\u0074e\")] < ((196, 252, 218, 4) & (3 ^ 6))) {" fullword ascii
    $s3 = "totalBarrel = (((1 & 1) + (([+[]]))), this);" fullword ascii
    $s4 = "f\\u006ce\", function String.prototype.accompanyConfiguration() {" fullword ascii
    $s5 = "} catch(massSubject) {};" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    all of them
}