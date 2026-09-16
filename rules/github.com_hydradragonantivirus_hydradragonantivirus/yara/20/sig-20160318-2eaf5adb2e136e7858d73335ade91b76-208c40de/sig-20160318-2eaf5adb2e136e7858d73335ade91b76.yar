rule sig_20160318_2eaf5adb2e136e7858d73335ade91b76 {
  meta:
    description = "datamaliciousorder - file 20160318_2eaf5adb2e136e7858d73335ade91b76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3618d9972efa26e213902e45fd8335757a7a6ff8396e586e84360a95971f0e8c"

  strings:
    $s1  = "var gi = \"7H!wg\".charAt(2);var MNgAX = \"5jnbO9\".charAt(2);var p = \"\\x61\\x69\";var QPRN = \"a\\x67\";var VE = \"r\\x79 \";" ascii
    $s2  = "}}if (JCgHp){uHMSl = yoxmp[(VMoX) + (KAq) + (CjiKo) + (HEzMP) + (Tzhbo) + (PtN) + (x) + (fYHN) + (eiwTF)]((Y0) + (xa) + (NFHY)) " ascii
    $s3  = "return leNp - lVf;}var JCgHp = false;for (var n = 0; n < Qzd() * 1; n++){" fullword ascii
    $s4  = "+ (xj) + (aaL) + (DyBhw) + (l) + (f) + (JVFU);};function oOtA(){return (QVor) + (CyZKn) + (N) + (Y);};function Qzd(){return 22;}" ascii
    $s5  = "+ (CyZKn) + (N) + (Y)]((KBgp) + (PcOka) + (qNSoL) + (Yc));function Z(qRr){yoxmp[(LNES)](qRr, 0, 0);};function xwg(){return (G0) " ascii
    $s6  = ") + (JpP) + (LgD) + (Tbh) + (NLxy) + (eLrh) + (uyY) + (O0) + JCgHp ? (rvcd) + (KZ) + (EYFiD) : (K) + (cnIs) + (Yncm);}else{WScri" ascii
    $s7  = ", (lssEW) + (iGltE) + (V) + (Ioa) + (DQaym) + (MwuW) + (R) + (BLLa) + (wy) + (pI) + (oyp) + (qhb), false);Xpjq[(Wi)]();while (Xp" ascii
    $s8  = ";function u(){" fullword ascii
    $s9  = "JCgHp = true;" fullword ascii
    $s10 = "var G = new this[(Zosk)]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}