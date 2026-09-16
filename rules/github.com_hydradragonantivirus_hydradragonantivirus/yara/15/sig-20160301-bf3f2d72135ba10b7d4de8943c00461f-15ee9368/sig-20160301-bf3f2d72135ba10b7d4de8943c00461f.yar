rule sig_20160301_bf3f2d72135ba10b7d4de8943c00461f {
  meta:
    description = "datamaliciousorder - file 20160301_bf3f2d72135ba10b7d4de8943c00461f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bb7c7f8883bdeb8d5c27cc6c28d64eeecf0437dfb035080826e2b5edc613404"

  strings:
    $s1 = "regressionEconomy = (((31 - 31) | (1 ^ 0)), this);" fullword ascii
    $s2 = "terrorViolet[(\"\\u0073ex\", function String.prototype.prologueProduce() {" fullword ascii
    $s3 = "while (seriousTypical[(\"\\u0070eri\" + \"\\u006fd\", \"p\" + \"\\u006f\\u0072\" + \"\\u0074\" + \"\\u0061l\", \"re\\u0061\" + " ascii
    $s4 = "while (seriousTypical[(\"\\u0070eri\" + \"\\u006fd\", \"p\" + \"\\u006f\\u0072\" + \"\\u0074\" + \"\\u0061l\", \"re\\u0061\" + " ascii
    $s5 = "} catch (inspectorResolution) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}