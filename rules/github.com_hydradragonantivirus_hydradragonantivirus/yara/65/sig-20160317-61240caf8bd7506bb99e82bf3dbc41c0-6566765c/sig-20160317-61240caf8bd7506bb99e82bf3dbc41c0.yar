rule sig_20160317_61240caf8bd7506bb99e82bf3dbc41c0 {
  meta:
    description = "datamaliciousorder - file 20160317_61240caf8bd7506bb99e82bf3dbc41c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ad6c255da11a53d0e2a6901138483275adf7c86e7e2c8a6590c1c3e93a24b22"

  strings:
    $s1  = "var W = \"gain!\";var JJAG = \"ry\\x20a\";var XFq = \",\\x20\\x74\";var pX = \"se\";var BlE = \"Plea\";var OrUT = \"\\x3162\";va" ascii
    $s2  = "T);}else{WScript.Echo((BlE) + (pX) + (XFq) + (JJAG) + (W));}" fullword ascii
    $s3  = "}}if (PKzLz){lF = v[(KP) + (tBMW) + (ssUQ) + (uKGsp) + (gI) + (fy) + (TkjQ) + (ByM) + (zhE) + (HY)]((Ll) + (nf)) + (YPBFV) + (os" ascii
    $s4  = "Hz0), false);ULrJJ[(m)]();while (ULrJJ[(TVX) + (NX) + (I0)] < 4 ) {WScript[(l)](SSo() * 10)};sSa = WScript[KVep()]((sc) + (cvQJ)" ascii
    $s5  = "return PG - uiN;}var PKzLz = false;for (var zAgY = 0; zAgY < SSo() * 1; zAgY++){" fullword ascii
    $s6  = "var lh = new this[(FZneV) + (f)]();" fullword ascii
    $s7  = "eturn (L) + (MupSE) + (yk) + (U);};function SSo(){return 22;};function yzLy(){" fullword ascii
    $s8  = "PtukG));function jnsM(NMZSk){v[(YH)](NMZSk, 0, 0);};function XIs(){return (RE) + (Nn) + (G) + (cPo) + (WloC);};function KVep(){r" ascii
    $s9  = "PKzLz = true;" fullword ascii
    $s10 = "var W = \"gain!\";var JJAG = \"ry\\x20a\";var XFq = \",\\x20\\x74\";var pX = \"se\";var BlE = \"Plea\";var OrUT = \"\\x3162\";va" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}