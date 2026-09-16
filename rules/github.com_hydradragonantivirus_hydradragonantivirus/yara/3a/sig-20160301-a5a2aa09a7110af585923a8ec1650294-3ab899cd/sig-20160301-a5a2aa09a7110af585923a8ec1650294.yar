rule sig_20160301_a5a2aa09a7110af585923a8ec1650294 {
  meta:
    description = "datamaliciousorder - file 20160301_a5a2aa09a7110af585923a8ec1650294.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cda43f4a9488b4586d7f37bdf043fd1680d8dc3e470d482e3cfe6e82326e514"

  strings:
    $s1 = "while (princeSum[(\"a\\u0075\\u0064\\u0069\\u0065\" + \"\\u006ec\\u0065\", \"cor\" + \"t\\u0065g\" + \"\\u0065\", \"\\u006c\\u00" ascii
    $s2 = "while (princeSum[(\"a\\u0075\\u0064\\u0069\\u0065\" + \"\\u006ec\\u0065\", \"cor\" + \"t\\u0065g\" + \"\\u0065\", \"\\u006c\\u00" ascii
    $s3 = "u0072\\u0073iv\" + \"\\u0065\", function String.prototype.equivalentNegative() {" fullword ascii
    $s4 = "princeSum = bottleSpecification[(\"i\\u006e\\u0073tru\" + \"\\u0063t\" + \"io\\u006e\", \"co\\u006et\\u0072\" + \"\\u0069\\u0062" ascii
    $s5 = "bottleSpecification = ((1 * 1), this);" fullword ascii
    $s6 = "} catch (paroleSignal) {};" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    all of them
}