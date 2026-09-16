rule sig_20160303_38759b07ae22b1912c34a77f9f05aef2 {
  meta:
    description = "datamaliciousorder - file 20160303_38759b07ae22b1912c34a77f9f05aef2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea5de49c007a826b001360ea4fee379127bbae0f08686d8fc20752120efac5d6"

  strings:
    $s1 = "while (totalParity[cycleQualification + epilogueIntelligence + anarchyFunction] < ((13) - (4 * 2 + 1))) {" fullword ascii
    $s2 = "dual + symmetricalRevue + finishBattery + importClub + conceptionBalance + priceJunior + imitateApostrophe + sponsorAcrobat + nu" ascii
    $s3 = "computerCombine = (3 * 3 * 7 * (1 * 2) * (0 | 2), (((7 + 3) | (3 * 4 + 1)), this));" fullword ascii
    $s4 = "ion + moralRegistry](studioMembrane + displayMate) + attributeTelephone + minuteAnarchy + plusUniform + medicinePreamble + focus" ascii
    $s5 = "priceJunior = (function String.prototype.militaryTelevision() {" fullword ascii
    $s6 = "Dollar;" fullword ascii
    $s7 = "} catch (diskReaction) {};" fullword ascii

  condition:
    uint16(0) == 0x6173 and
    all of them
}