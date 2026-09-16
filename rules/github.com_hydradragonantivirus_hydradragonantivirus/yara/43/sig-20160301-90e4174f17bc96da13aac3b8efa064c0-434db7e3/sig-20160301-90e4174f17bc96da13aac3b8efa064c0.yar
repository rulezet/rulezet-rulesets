rule sig_20160301_90e4174f17bc96da13aac3b8efa064c0 {
  meta:
    description = "datamaliciousorder - file 20160301_90e4174f17bc96da13aac3b8efa064c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a948f9db31b2b9e3e085249fe1134a21480a71a956c899ceba70283977df801"

  strings:
    $s1 = "while(masterImperative[(\"\\u006eo\\u0073\\u0065\", \"salu\\u0074\\u0065\", \"am\\u0070u\\u0074\" + \"a\" + \"\\u0074\\u0065\", " ascii
    $s2 = "masterImperative[(\"p\" + \"\\u0072ov\" + \"\\u006f\\u0063\\u0061t\" + \"i\" + \"on\", \"d\\u006f\\u0067\" + \"\\u006d\" + \"\\u" ascii
    $s3 = "while(masterImperative[(\"\\u006eo\\u0073\\u0065\", \"salu\\u0074\\u0065\", \"am\\u0070u\\u0074\" + \"a\" + \"\\u0074\\u0065\", " ascii
    $s4 = "officialCompact = (((86, 205, 1) & (14 / 14)), this);" fullword ascii
    $s5 = "} catch(transportGuide) {};" fullword ascii

  condition:
    uint16(0) == 0x666f and
    all of them
}