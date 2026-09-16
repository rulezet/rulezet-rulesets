rule sig_20160317_2d41ebbac737c5e1458e281eaba0e3fd {
  meta:
    description = "datamaliciousorder - file 20160317_2d41ebbac737c5e1458e281eaba0e3fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "315154a4c23ce156c24eb4bced9ff3e8f0d1520bcba219af2e8aac1dfe90f90b"

  strings:
    $s1  = "var A0 = \"!3xg\".charAt(0);var Tp = \"nA5n7i\".charAt(0);var QqN = \"si6mA\".charAt(1);var rZCt = \"\\x61\\x67\\x61\";var oU = " ascii
    $s2  = ") + (bOgOb) + D ? (k) + (dUmmZ) + (kdVzs) + (zrX) : (jVT) + (yMGX) + (H);}else{WScript.Echo((OXy) + (dcEyg) + (v0) + (oU) + (rZC" ascii
    $s3  = ";var lZ = \"ateO\\x62\";var R = \"Cre\";r = WScript[(R) + (lZ) + (KaJ) + (OM)]((PSli) + (gvCt) + (TDx) + (dJU));function pGpVI(w" ascii
    $s4  = "return q - kIxN;}var D = false;for (var eY = 0; eY < rAg() * 1; eY++){" fullword ascii
    $s5  = "}}if (D){jN = r[(Isf) + (xl) + (K) + (wvaxr) + (A) + (GQl) + (sK) + (f)]((DR) + (Ql)) + (WSfNH) + (ev) + (Bw) + (sRim); EfF = bA" ascii
    $s6  = ") + (OM);};function rAg(){return 22;};function LRMi(){" fullword ascii
    $s7  = "var kf = new this[(p) + (Kl)]();" fullword ascii
    $s8  = "hk)](w, 0, 0);};function bAe(){return (QTZ) + (Saln) + (CoBX) + (Dm) + (wheeX) + (mlg);};function Lvq(){return (R) + (lZ) + (KaJ" ascii
    $s9  = "m) + (iUjcF) + (VsP) + (ZkJ) + (QL) + (gl) + (enWMa), false);BcAp[(zGEPt)]();while (BcAp[(pWKw) + (YMME) + (ZhNUi)] < 4 ) {WScri" ascii
    $s10 = "D = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}