rule sig_20160514_cdd12445d8af540fdee85345914a30a1 {
  meta:
    description = "datamaliciousorder - file 20160514_cdd12445d8af540fdee85345914a30a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da2aede6820ad28b246ea6de8cc7fd15b1ea09040d2d56cdeac89d4854b8d09"

  strings:
    $s1  = "while (LKelMyX < YmyGqg - (6523 + 1873 - 8394)) {" fullword ascii
    $s2  = "return rsLC;" fullword ascii
    $s3  = "function oUxOMMX(rGSM, eSO) {" fullword ascii
    $s4  = "return HbxYQYK;" fullword ascii
    $s5  = "function kwEJw() {" fullword ascii
    $s6  = "if (gBC === false) {" fullword ascii
    $s7  = "return gzSJM;" fullword ascii
    $s8  = "function LxipEF() {" fullword ascii
    $s9  = "function Vhm() {" fullword ascii
    $s10 = "return glOed;" fullword ascii
    $s11 = "var SQcIdb = String;" fullword ascii
    $s12 = "return XyDmc;" fullword ascii
    $s13 = "function FUjlKM() {" fullword ascii
    $s14 = "return khpV;" fullword ascii
    $s15 = "function itJ(rtwjdld, kdkndmd) {" fullword ascii
    $s16 = "function mZPFxwY(CuxlfK, DyTDxwl) {" fullword ascii
    $s17 = "return kMZvAM;" fullword ascii
    $s18 = "var oygtG = true;" fullword ascii
    $s19 = "return dbKeRDC;" fullword ascii
    $s20 = "function hLUlejG() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}