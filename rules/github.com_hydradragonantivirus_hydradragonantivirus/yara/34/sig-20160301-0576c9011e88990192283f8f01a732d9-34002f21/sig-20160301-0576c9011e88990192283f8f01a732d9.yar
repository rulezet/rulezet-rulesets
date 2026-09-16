rule sig_20160301_0576c9011e88990192283f8f01a732d9 {
  meta:
    description = "datamaliciousorder - file 20160301_0576c9011e88990192283f8f01a732d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbea91fa3230c157293bf8be6d8382a48b27650b9dc816c441094010510375dd"

  strings:
    $s1 = "while(absurdObligation[(\"p\\u0072\\u0065ss\", \"\\u0072\" + \"\\u0065a\" + \"\\u0064\\u0079\\u0073ta\\u0074\" + \"\\u0065\")] <" ascii
    $s2 = "lectureBalloon = ((1 + 0), this);" fullword ascii
    $s3 = "while(absurdObligation[(\"p\\u0072\\u0065ss\", \"\\u0072\" + \"\\u0065a\" + \"\\u0064\\u0079\\u0073ta\\u0074\" + \"\\u0065\")] <" ascii
    $s4 = "decadeTandem[(\"t\\u0065\\u0063h\" + \"niq\" + \"\\u0075\\u0065\", \"\\u0074ac\\u0074\" + \"ics\", \"a\\u0069\\u0072p\\u006c\" +" ascii
    $s5 = "decadeTandem[(\"t\\u0065\\u0063h\" + \"niq\" + \"\\u0075\\u0065\", \"\\u0074ac\\u0074\" + \"ics\", \"a\\u0069\\u0072p\\u006c\" +" ascii
    $s6 = "} catch(serialRadiation) {};" fullword ascii

  condition:
    uint16(0) == 0x656c and
    all of them
}