rule sig_20160301_da33fe653e1aeadcb82b9ecea81fbfe2 {
  meta:
    description = "datamaliciousorder - file 20160301_da33fe653e1aeadcb82b9ecea81fbfe2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae87e515599b4e073885d40a6484f95f1d1c62630db9bfa043ceb32d647f44dd"

  strings:
    $s1 = "while (clubVulgar[(\"\\u0073\\u0074a\\u0074\\u0069s\" + \"\\u0074i\" + \"cs\", \"\\u0069l\" + \"\\u006c\\u0075s\" + \"t\\u0072\"" ascii
    $s2 = "while (clubVulgar[(\"\\u0073\\u0074a\\u0074\\u0069s\" + \"\\u0074i\" + \"cs\", \"\\u0069l\" + \"\\u006c\\u0075s\" + \"t\\u0072\"" ascii
    $s3 = "tabletTandem = (((11 & 15) / ((((([+!+[]])) + \"\" + (([+!+[]])))))), this);" fullword ascii
    $s4 = "} catch (practicalCooperation) {};" fullword ascii
    $s5 = "argumentPredicate = imitationBarge[(\"\\u0069n\\u0074\\u0065\\u0072\\u0070\" + \"r\\u0065\\u0074\", function String.prototype.bl" ascii
    $s6 = "argumentPredicate = imitationBarge[(\"\\u0069n\\u0074\\u0065\\u0072\\u0070\" + \"r\\u0065\\u0074\", function String.prototype.bl" ascii

  condition:
    uint16(0) == 0x6174 and
    all of them
}