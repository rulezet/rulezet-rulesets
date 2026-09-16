rule sig_20160301_f2f006420d8dc2f45e02af88ce9104e8 {
  meta:
    description = "datamaliciousorder - file 20160301_f2f006420d8dc2f45e02af88ce9104e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "489615a72557408c7da023271a9429b4d2d739e0dc01024a5038ab440832e1a4"

  strings:
    $s1 = "falseLimit = ((1 + (16 - 16)), this);" fullword ascii
    $s2 = "while(protectorOrgan[(\"org\" + \"an\", \"\\u0062la\\u006e\" + \"k\", \"\\u0072e\\u0061d\\u0079s\" + \"\\u0074ate\")] < ((0 ^ 4)" ascii
    $s3 = "acrobatRum = cyberneticsDuplicate[(\"a\\u006e\" + \"o\\u006e\\u0079\" + \"\\u006do\" + \"\\u0075\\u0073\", function String.proto" ascii
    $s4 = "acrobatRum = cyberneticsDuplicate[(\"a\\u006e\" + \"o\\u006e\\u0079\" + \"\\u006do\" + \"\\u0075\\u0073\", function String.proto" ascii
    $s5 = "} catch(juniorConvention) {};" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    all of them
}