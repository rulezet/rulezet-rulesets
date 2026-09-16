rule sig_20160317_7bd075e8efe5a5b4d08732e94d9b6274 {
  meta:
    description = "datamaliciousorder - file 20160317_7bd075e8efe5a5b4d08732e94d9b6274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2502ac34068d1007081eecba6aa220a2e51b0c43009ae3c3a66731d7917b5c5a"

  strings:
    $s1  = "var MiV = \"n!\";var nrw = \"a\\x69\";var bHf = \"g4\".charAt(0);var C0 = \"r\\x79\\x20a\";var PadX = \"\\x2c t\";var CJtWM = \"" ascii
    $s2  = " + (L1) + (i) + EaRu ? (ef) + (whrsU) + (n) : (oAcx) + (Yl) + (wU) + (F);}else{WScript.Echo((LUQCc) + (akE) + (CJtWM) + (PadX) +" ascii
    $s3  = "2\";UNeP = WScript[(Ad) + (q) + (DK) + (uID) + (hPrM)]((L) + (jMxJH) + (CKb));function W(o){UNeP[(uZRu)](o, 0, 0);};function toP" ascii
    $s4  = "return ti - YQi;}var EaRu = false;for (var yZ = 0; yZ < xer() * 1; yZ++){" fullword ascii
    $s5  = "}}if (EaRu){tB = UNeP[(Tg) + (hmFg) + (PKP) + (tZm) + (QNJKp) + (ahNdZ) + (Mt) + (ltfg) + (sSNgP) + (sULn)]((xJPGi) + (u0)) + (W" ascii
    $s6  = "c(){return (qtQ) + (oN) + (B) + (TZDKn) + (rx);};function BHOk(){return (Ad) + (q) + (DK) + (uID) + (hPrM);};function xer(){retu" ascii
    $s7  = "VBPb) + (XAOO) + (Tdf) + (EMdeU) + (Z) + (Jkae) + (SwTO) + (qgF) + (U0), false);eM[(nie) + (WPV)]();while (eM[(PGYQ) + (DuBX) + " ascii
    $s8  = "rn 22;};function jJ(){" fullword ascii
    $s9  = "var Rp = new this[(u)]();" fullword ascii
    $s10 = "EaRu = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}