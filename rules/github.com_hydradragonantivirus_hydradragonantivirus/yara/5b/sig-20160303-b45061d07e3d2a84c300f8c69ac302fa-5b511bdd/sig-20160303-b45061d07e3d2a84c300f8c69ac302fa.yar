rule sig_20160303_b45061d07e3d2a84c300f8c69ac302fa {
  meta:
    description = "datamaliciousorder - file 20160303_b45061d07e3d2a84c300f8c69ac302fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e60d36e3c1d039ea6c47d8858997afc0a7ec09abdbe6f8c4ac2413c1c889958"

  strings:
    $s1 = "trivialCategory = (((Math.pow(268, 2) - 71620)), (((([!+[] + !+[] + !+[]]) * ([!+[] + !+[]]) * ([!+[] + !+[]]) * ([!+[] + !+[] +" ascii
    $s2 = "while (imitationComplex[inductionCommittee + cycleChance + actLiterature] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s3 = " !+[]]) * ([!+[] + !+[] + !+[]])) / (19 ^ 8)), this));" fullword ascii
    $s4 = "civilizationSymbol = (function String.prototype.objectivePortal() {" fullword ascii
    $s5 = "} catch (stopClip) {};" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    all of them
}