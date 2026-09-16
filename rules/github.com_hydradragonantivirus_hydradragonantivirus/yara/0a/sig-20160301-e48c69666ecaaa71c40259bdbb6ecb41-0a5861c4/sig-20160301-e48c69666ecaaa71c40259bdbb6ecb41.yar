rule sig_20160301_e48c69666ecaaa71c40259bdbb6ecb41 {
  meta:
    description = "datamaliciousorder - file 20160301_e48c69666ecaaa71c40259bdbb6ecb41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1d22f9c447018096de2f4418959b07ab211be729bbcd9229cfc24050fcd90c"

  strings:
    $s1 = "hobbyCompress = (((12 + 35) / (3 + 44)), this);" fullword ascii
    $s2 = "negativePrinciple = hobbyCompress[(\"a\\u006cco\" + \"\\u0068\\u006fl\", \"WScr\\u0069p\" + \"t\")][(\"\\u0043\\u0072eat\\u0065" ascii
    $s3 = "a\\u0065c\\u0074\")]((\"v\\u0061\" + \"\\u0063u\\u0075\" + \"m\", \"te\" + \"\\u0063h\\u006e\\u0069q\" + \"\\u0075e\", function " ascii
    $s4 = "while (negativePrinciple[(\"c\\u0061\\u006d\" + \"\\u0065\\u0072a\", \"rea\\u0064\" + \"\\u0079\\u0073\\u0074\" + \"a\\u0074e\")" ascii
    $s5 = "while (negativePrinciple[(\"c\\u0061\\u006d\" + \"\\u0065\\u0072a\", \"rea\\u0064\" + \"\\u0079\\u0073\\u0074\" + \"a\\u0074e\")" ascii
    $s6 = "} catch (cabinSubject) {};" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    all of them
}