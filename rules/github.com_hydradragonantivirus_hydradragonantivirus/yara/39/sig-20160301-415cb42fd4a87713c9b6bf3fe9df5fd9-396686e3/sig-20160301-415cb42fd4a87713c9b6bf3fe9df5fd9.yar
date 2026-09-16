rule sig_20160301_415cb42fd4a87713c9b6bf3fe9df5fd9 {
  meta:
    description = "datamaliciousorder - file 20160301_415cb42fd4a87713c9b6bf3fe9df5fd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95f40cff7e5ee42f75277b0c2b6ee33f53a181c4b5acd74faf66e92f10e60326"

  strings:
    $s1 = "u0072e\\u006d\" + \"e\", function String.prototype.transportationClan() {" fullword ascii
    $s2 = "extractAlternative[(\"d\" + \"\\u0069a\" + \"\\u0067\" + \"r\" + \"\\u0061m\", \"bu\\u0073\" + \"\\u0069\" + \"\\u006e\\u0065\" " ascii
    $s3 = "while (extractAlternative[(\"\\u0070\\u0072o\" + \"\\u0063edu\\u0072\" + \"\\u0065\", \"\\u0064\\u0069\\u0073\" + \"cre\\u0074" ascii
    $s4 = "while (extractAlternative[(\"\\u0070\\u0072o\" + \"\\u0063edu\\u0072\" + \"\\u0065\", \"\\u0064\\u0069\\u0073\" + \"cre\\u0074" ascii
    $s5 = "campaignVolcano = (((0 / 14) | (6 - 5)), this);" fullword ascii
    $s6 = "} catch (stadiumRhythm) {};" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    all of them
}