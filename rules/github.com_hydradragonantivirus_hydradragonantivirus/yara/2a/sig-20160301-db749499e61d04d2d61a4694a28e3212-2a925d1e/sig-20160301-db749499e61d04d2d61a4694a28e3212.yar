rule sig_20160301_db749499e61d04d2d61a4694a28e3212 {
  meta:
    description = "datamaliciousorder - file 20160301_db749499e61d04d2d61a4694a28e3212.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7040a5c3344d2ac2647e842c3624d9c3b736051188cc85710311731770004d79"

  strings:
    $s1 = "logicCode = (((3 | 26) - (21 + 5)), this);" fullword ascii
    $s2 = "controlSignal = logicCode[(\"de\\u0063ad\\u0065\", \"ba\" + \"\\u006e\\u0064ag\\u0065\", function String.prototype.initialMeridi" ascii
    $s3 = "while (controlSignal[(\"\\u0061\\u0063t\\u0069\\u006fn\", \"i\" + \"\\u006e\\u0064\\u0065\\u0078\", \"gu\\u0069d\\u0065\", \"c\"" ascii
    $s4 = "while (controlSignal[(\"\\u0061\\u0063t\\u0069\\u006fn\", \"i\" + \"\\u006e\\u0064\\u0065\\u0078\", \"gu\\u0069d\\u0065\", \"c\"" ascii
    $s5 = "} catch (versionInfinitive) {};" fullword ascii

  condition:
    uint16(0) == 0x6f6c and
    all of them
}