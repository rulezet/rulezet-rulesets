rule sig_20160301_07df9905a966c67bbcf026b44f2233e2 {
  meta:
    description = "datamaliciousorder - file 20160301_07df9905a966c67bbcf026b44f2233e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aacf207428c85b0c0c47ee35e0b5c0e400ee8fbcebf57f36aee66e8696047b0"

  strings:
    $s1 = "while (filterMusic[(\"\\u0064ef\" + \"\\u006f\" + \"\\u0072m\" + \"\\u0061\\u0074io\" + \"n\", \"\\u006d\\u0065\\u006d\" + \"b\"" ascii
    $s2 = "uniqueModify = (\"\\u0075ni\" + \"v\" + \"e\\u0072\\u0073it\" + \"\\u0079\", \"\\u0072e\\u0073\\u0069\\u0064\" + \"en\" + \"t\"," ascii
    $s3 = "toxicBalloon = (((1 & 1) | (0 + 0)), this);" fullword ascii
    $s4 = "uniqueModify = (\"\\u0075ni\" + \"v\" + \"e\\u0072\\u0073it\" + \"\\u0079\", \"\\u0072e\\u0073\\u0069\\u0064\" + \"en\" + \"t\"," ascii
    $s5 = "while (filterMusic[(\"\\u0064ef\" + \"\\u006f\" + \"\\u0072m\" + \"\\u0061\\u0074io\" + \"n\", \"\\u006d\\u0065\\u006d\" + \"b\"" ascii
    $s6 = "} catch (inversionImpression) {};" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    all of them
}