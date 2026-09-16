rule sig_20160318_d515f2c462459a826d350bfa637ff8e2 {
  meta:
    description = "datamaliciousorder - file 20160318_d515f2c462459a826d350bfa637ff8e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "967a0f5d685d25830ff59c1e7923933636aa0fd37b2e151d54215a84e226af28"

  strings:
    $s1 = "var mapZ = \"a\\x69n!\";var V0 = \" \\x61g\";var uUnE = \"\\x20t\\x72y\";var t = \"ase\\x2c\";var by = \"P\\x6ce\";var rtjL = \"" ascii
    $s2 = "}}if (nZw){g = EvO[(DQV) + (YytJv) + (mhJ) + (mYGu) + (O) + (qgtEe) + (VKc)]((DWDh) + (uka) + (Ulk)) + (NsTb) + (L) + (zvIsw) + " ascii
    $s3 = ") + (rtjL);}else{WScript.Echo((by) + (t) + (uUnE) + (V0) + (mapZ));}" fullword ascii
    $s4 = "return DfzW - J;}var nZw = false;for (var ks = 0; ks < MnnG() * 1; ks++){" fullword ascii
    $s5 = "(fNcC) + (fAS) + (SS) + (sEF) + (R) + (KPjez));function qVv(EGD){EvO[(rvRz)](EGD, 0, 0);};function PSsIz(){return (H) + (fsWRD) " ascii
    $s6 = "var BNL = new this[(EnA) + (Qfv) + (Qhtu)]();" fullword ascii
    $s7 = "+ (Zs) + (HDGm) + (HQk) + (B);};function FJRC(){return (a) + (v0) + (PyK) + (G) + (mf);};function MnnG(){return 22;};function k(" ascii
    $s8 = "JRMSj) + (YlsKi) + (cd) + (uy) + (STGBz) + (jjh) + (g2) + (rtX) + (uh), false);EDE[(chBO) + (rcc) + (MVzi)]();while (EDE[(S) + (" ascii
    $s9 = "nZw = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}