rule sig_20160301_a46adff9f387121258a1f7b4a322c2d2 {
  meta:
    description = "datamaliciousorder - file 20160301_a46adff9f387121258a1f7b4a322c2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13afa297c9f27b633c282c4da67e26550c14b4d0f8935300e550f469f051a70a"

  strings:
    $s1 = "statusNumeration = ((2 * 2 * 7, (14 + 17)), this);" fullword ascii
    $s2 = "while(isolatePress[(\"\\u0063\\u006fo\\u0070e\\u0072ati\\u006fn\", \"rea\\u0064y\\u0073t\\u0061\\u0074\\u0065\")] < ((([+[]])) ^" ascii
    $s3 = "isolatePress = statusNumeration[(\"\\u0074\\u0068es\\u0069s\", \"vis\\u0069\\u0074\", \"\\u0073c\\u0061l\\u0070e\\u006c\", funct" ascii
    $s4 = "isolatePress = statusNumeration[(\"\\u0074\\u0068es\\u0069s\", \"vis\\u0069\\u0074\", \"\\u0073c\\u0061l\\u0070e\\u006c\", funct" ascii
    $s5 = "} catch(illusionMoment) {};" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    all of them
}