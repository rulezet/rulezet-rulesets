rule sig_20160301_5fc247dcd1d438b4409568b3b165c8ce {
  meta:
    description = "datamaliciousorder - file 20160301_5fc247dcd1d438b4409568b3b165c8ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83a0ed6f16891840286441a3f4132fa2511a9d6234060b5867633f0f72da45fe"

  strings:
    $s1 = "astronautNeutral = effectNumeration[(\"normal\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"combination\", \"brilliant\"" ascii
    $s2 = "translationResource = (((Math.pow(169, 2) - 28465) * (2 | 0) + (92, 36)), this);" fullword ascii
    $s3 = "astronautNeutral = effectNumeration[(\"normal\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"combination\", \"brilliant\"" ascii
    $s4 = "  ballastStorm[(\"laboratory\", \"clan\", \"blank\", function String.prototype.postscriptTick() {" fullword ascii
    $s5 = "while (chancePerson[(\"shunt\", \"readystate\")] < ((49 + 27) / (1 | 19))) {" fullword ascii
    $s6 = "} catch (raceCombine) {};" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    all of them
}