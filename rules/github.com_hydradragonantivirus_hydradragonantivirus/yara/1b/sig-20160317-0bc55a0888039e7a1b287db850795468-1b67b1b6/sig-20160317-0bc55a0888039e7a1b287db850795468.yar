rule sig_20160317_0bc55a0888039e7a1b287db850795468 {
  meta:
    description = "datamaliciousorder - file 20160317_0bc55a0888039e7a1b287db850795468.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d2c17fbca9aab2177fd15c60ad8434a8ab66ea4493d90194e8f68de948ac31"

  strings:
    $s1 = "var De = \"i\\x6e\\x21\";var XK = \"\\x61\\x67a\";var QAsoN = \"y \";var RMDq = \"bA0krU\".charAt(4);var h2 = \", t\";var PCU = " ascii
    $s2 = "}}if (zGmeF){q = appq[(DRqVF) + (GHfdu) + (Nn) + (FD) + (WzX) + (CuyAG) + (Wyw) + (U0)]((uW) + (Z) + (mS)) + (ac) + (zS) + (HPuA" ascii
    $s3 = "q = WScript[(U) + (bFr) + (XZ) + (OrtKZ) + (g)]((SyL) + (h) + (bDUqI) + (xoBIQ) + (aONVi) + (aWKM));function LmSze(mi){appq[(Bwo" ascii
    $s4 = "return Ij - KK;}var zGmeF = false;for (var lfZCx = 0; lfZCx < hnihs() * 1; lfZCx++){" fullword ascii
    $s5 = "gK)](mi, 0, 0);};function iEr(){return (Apvot) + (D) + (dNEy) + (teIa);};function AMq(){return (U) + (bFr) + (XZ) + (OrtKZ) + (g" ascii
    $s6 = "var Fl = new this[(qJPXO) + (oJomQ)]();" fullword ascii
    $s7 = "g) + (KqcIl), (FL) + (vrvyG) + (IUOd) + (UCx) + (C) + (AYPq) + (bmF) + (bB) + (PMeVv), false);YhOw[(bkL)]();while (YhOw[(WomNN) " ascii
    $s8 = "zGmeF = true;" fullword ascii
    $s9 = ");};function hnihs(){return 22;};function n(){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}