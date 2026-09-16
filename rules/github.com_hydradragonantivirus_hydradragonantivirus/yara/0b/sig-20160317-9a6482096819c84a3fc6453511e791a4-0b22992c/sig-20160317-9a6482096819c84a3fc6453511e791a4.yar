rule sig_20160317_9a6482096819c84a3fc6453511e791a4 {
  meta:
    description = "datamaliciousorder - file 20160317_9a6482096819c84a3fc6453511e791a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83f21b36b04f4ce4c0829749b6df3ac9842975bb4864ef129021e3d06a939b04"

  strings:
    $s1 = "var BDDSz = \"\\x61\\x69\\x6e!\";var kV = \"ry a\\x67\";var JXP = \"t8\".charAt(0);var HqYm = \", \";var GH = \"lea\\x73e\";var " ascii
    $s2 = "+ (CIM) + (fgost) + Xcdqn ? (VxnIu) + (L1) + (Jcbz) : (erC) + (UVCWq);}else{WScript.Echo((DmsZN) + (GH) + (HqYm) + (JXP) + (kV) " ascii
    $s3 = "return iU - W;}var Xcdqn = false;for (var n = 0; n < Azk() * 1; n++){" fullword ascii
    $s4 = "}}if (Xcdqn){jMa = DsD[(qNNRJ) + (YfRAb) + (WK) + (LIqrk) + (ys) + (BT) + (j) + (nT)]((rO) + (U)) + (K) + (en) + (y) + (cY); G =" ascii
    $s5 = "var Ok = new this[(Gvrz) + (OUzA)]();" fullword ascii
    $s6 = "+ (WrST) + (beQWX) + (UZAPm) + (vRkZ) + (tW) + (OViU) + (jH) + (eRKLL) + (FYQ), false);Qu[(kHPF)]();while (Qu[(TrA) + (ZkNr) + (" ascii
    $s7 = "kZIZ) + (fXeic) + (nKucc) + (hYtWw));function GUvC(JYw){DsD[(RAgy) + (L)](JYw, 0, 0);};function GyB(){return (mODL) + (gtDX) + (" ascii
    $s8 = "kaPE) + (OL) + (qZsmD);};function RQzS(){return (hB) + (D) + (NFnJ) + (wkaxa) + (o) + (TJI);};function Azk(){return 22;};functio" ascii
    $s9 = "Xcdqn = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}