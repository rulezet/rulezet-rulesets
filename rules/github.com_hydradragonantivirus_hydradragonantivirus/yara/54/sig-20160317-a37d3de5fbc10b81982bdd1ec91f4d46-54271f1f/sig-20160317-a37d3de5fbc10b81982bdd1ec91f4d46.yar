rule sig_20160317_a37d3de5fbc10b81982bdd1ec91f4d46 {
  meta:
    description = "datamaliciousorder - file 20160317_a37d3de5fbc10b81982bdd1ec91f4d46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b832a52d54fe50c21ed6c8002a504c01a21be3861ddb9118099d59e1a880e55c"

  strings:
    $s1 = "var DiM = \"n!\";var bZX = \" agai\";var L = \", try\";var vTBD = \"e\\x61\\x73e\";var nPfIH = \"P\\x6c\";var NEjC = \"2\";var n" ascii
    $s2 = "}}if (bMT){VmLnX = G[(rkRS) + (wm) + (Ij) + (hwWVj) + (uZXWt) + (f0) + (Bfvg) + (Ajs) + (utn) + (kOoDV)]((vb) + (JvzL) + (K) + (" ascii
    $s3 = "return ZR - byI;}var bMT = false;for (var BN = 0; BN < VJDg() * 1; BN++){" fullword ascii
    $s4 = "Tttz) + (cVKF) + (V0) + (fWg) + (Qmc) + (KG) + (auZI) + (lKI) + (UrRwk) + (Pz), false);HP[(hgir) + (IvMq)]();while (HP[(KAI) + (" ascii
    $s5 = "(qDxi) + (Sm) + (gE) + (UH) + (fxjC) + (nmqMW));function i(py){G[(S) + (HtJ)](py, 0, 0);};function PiHG(){return (x) + (XtJcJ) +" ascii
    $s6 = " (jS) + (g) + (MV) + (SNF) + (tVaqt);};function pFr(){return (O) + (GIpq) + (EfgZ) + (cgzqC);};function VJDg(){return 22;};funct" ascii
    $s7 = "var qbsN = new this[(cmkB)]();" fullword ascii
    $s8 = "bMT = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}