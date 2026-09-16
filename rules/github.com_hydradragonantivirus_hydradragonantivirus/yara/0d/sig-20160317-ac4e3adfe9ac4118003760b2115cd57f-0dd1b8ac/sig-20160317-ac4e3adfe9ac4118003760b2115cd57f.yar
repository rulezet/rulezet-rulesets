rule sig_20160317_ac4e3adfe9ac4118003760b2115cd57f {
  meta:
    description = "datamaliciousorder - file 20160317_ac4e3adfe9ac4118003760b2115cd57f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b699510e44981d65468644b115aa02be1c49987162cd58fbae1369fc3ddc466b"

  strings:
    $s1  = "var dC = \"!\";var McK = \"a\\x69\\x6e\";var W0 = \"gEHvC\".charAt(0);var BhLj = \" \\x61\";var D = \"try\";var AmLy = \"as\\x65" ascii
    $s2  = "}}if (VRnpi){hQ = BEhd[(hoTSz) + (sCu) + (Qc) + (JiT) + (usWVe) + (mU) + (Vnow) + (c) + (f0) + (wg) + (j)]((XrxA) + (LdaDN) + (T" ascii
    $s3  = "}else{WScript.Echo((yzw) + (fdqY) + (AmLy) + (D) + (BhLj) + (W0) + (McK) + (dC));}" fullword ascii
    $s4  = "43r\\x65\\x61\";BEhd = WScript[(XI) + (l) + (pAbc)]((s) + (NNr) + (jvDzV) + (Hn));function f(BnzIK){BEhd[(ANJC)](BnzIK, 0, 0);};" ascii
    $s5  = "54\\x50\";var IrRH = \"TH67V\".charAt(0);var mOMO = \"\\x4cH\";var gtI = \"2.XM\";var iaV = \"\\x4d\\x53\\x58ML\";var ANJC = \"R" ascii
    $s6  = "return Lb - KKY;}var VRnpi = false;for (var w = 0; w < rSP() * 1; w++){" fullword ascii
    $s7  = "r OSv = \"d\";var jEzZz = \"as\";var PeAN = \"\\x61sdf\";var WEPN = \"74bfvq\".charAt(3);var tP = \"d\";var iIWcl = \"\\x69s\";v" ascii
    $s8  = "R) + (vwjQ) + (b) + (zi) + (iIWcl) + (tP) + (WEPN) + VRnpi ? (PeAN) + (jEzZz) + (OSv) + (t0) : (Cps) + (EXijW) + (ooTU) + (iWb);" ascii
    $s9  = ") + (S) + (AMDE) + (nCeRo) + (j0) + (GI) + (FvtSE) + (Otw) + (foQHd) + (Fy), false);ELDol[(xncC) + (kw)]();while (ELDol[(VtRx) +" ascii
    $s10 = "ction W(){return (iaV) + (gtI) + (mOMO) + (IrRH) + (Whm);};function ZRPBU(){return (XI) + (l) + (pAbc);};function rSP(){return 2" ascii
    $s11 = "VRnpi = true;" fullword ascii
    $s12 = "2;};function sF(){" fullword ascii
    $s13 = "var Uocar = new this[(GqCQ) + (GcN) + (NM)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}