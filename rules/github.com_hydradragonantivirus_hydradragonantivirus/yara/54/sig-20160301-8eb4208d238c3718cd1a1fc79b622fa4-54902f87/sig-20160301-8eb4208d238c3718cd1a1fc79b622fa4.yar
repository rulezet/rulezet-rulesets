rule sig_20160301_8eb4208d238c3718cd1a1fc79b622fa4 {
  meta:
    description = "datamaliciousorder - file 20160301_8eb4208d238c3718cd1a1fc79b622fa4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebc9c22b8030cb7d2e8f1a656b108568869d1affe35af7ce3fc7b9f4073a3043"

  strings:
    $s1 = "manuscriptProfile = ((([!+[] + !+[]]) * (((([!+[] + !+[] + !+[]])) + \"\" + (([+!+[]]))))), this);" fullword ascii
    $s2 = "Opera, ((2 ^ 0)));" fullword ascii
    $s3 = "\\u0062\\u0061\\u006ed\", \"s\\u0074\\u0072\\u0075ct\\u0075\\u0072\\u0065\", \"\\u0061\\u0064equat\\u0065\", \"Sle\\u0065\\u0070" ascii
    $s4 = "neutralIntegral[(\"\\u006d\\u006f\\u0064a\\u006c\", \"\\u0074\\u0065x\\u0074\", \"\\u0062it\", \"s\\u0061\\u0076\\u0065\\u0054o" ascii
    $s5 = "while (contrastZombie[(\"spe\\u0063i\\u0066ication\", \"\\u0072ead\\u0079\\u0073\\u0074\\u0061te\")] < ((0 | 0) + (2 * 2))) {" fullword ascii
    $s6 = "transmissionContribution = statisticalDistance[(\"\\u006f\\u0072ga\\u006e\\u0069\\u007aa\\u0074i\\u006fn\", function String.prot" ascii
    $s7 = "transmissionContribution = statisticalDistance[(\"\\u006f\\u0072ga\\u006e\\u0069\\u007aa\\u0074i\\u006fn\", function String.prot" ascii
    $s8 = "} catch (effectivePrince) {};" fullword ascii

  condition:
    uint16(0) == 0x616d and
    all of them
}