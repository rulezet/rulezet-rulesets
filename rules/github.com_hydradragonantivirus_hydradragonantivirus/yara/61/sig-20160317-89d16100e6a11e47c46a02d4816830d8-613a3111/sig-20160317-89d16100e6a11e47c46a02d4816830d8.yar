rule sig_20160317_89d16100e6a11e47c46a02d4816830d8 {
  meta:
    description = "datamaliciousorder - file 20160317_89d16100e6a11e47c46a02d4816830d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbdf500a49a03880366631c133d0f8b9c56c9f03169242168209b513bc7956c5"

  strings:
    $s1 = "var q = \"i\\x6e!\";var B = \"\\x67a\";var z = \" a\";var PaY = \", t\\x72\\x79\";var diCs = \"\\x73e\";var Aueee = \"le\\x61\";" ascii
    $s2 = "}}if (WaA){ELz = fb[(W) + (XBKkT) + (INwiJ) + (WQLV) + (NqAS) + (xXHuT)]((dHghT) + (JQY)) + (doY) + (XL) + (wpG) + (Vc) + (QWY);" ascii
    $s3 = "return wS - wM;}var WaA = false;for (var NC = 0; NC < mp() * 1; NC++){" fullword ascii
    $s4 = "(DV) + (qu) + (OzAu) + (rEyCd) + (WjUQ) + (i) + (TmXN) + (jF) + (et) + (ipwI), false);jCK[(BuMlR) + (aniTD)]();while (jCK[(dH) +" ascii
    $s5 = "var RFoZG = new this[(RvXpT) + (pE0) + (JoHAS)]();" fullword ascii
    $s6 = "(nZlPq)]((Vf) + (LhGRA) + (n) + (fAiyk) + (jAxRG) + (gGJ));function PrQH(aoc){fb[(GH) + (klDA)](aoc, 0, 0);};function jvAEB(){re" ascii
    $s7 = "turn (dwPl) + (HgT) + (ZCCpK) + (ZShEx) + (cSk) + (kQHyR);};function lB(){return (dPe) + (cLMpT) + (p) + (nZlPq);};function mp()" ascii
    $s8 = "{return 22;};function YO(){" fullword ascii
    $s9 = "WaA = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}