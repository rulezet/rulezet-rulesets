rule sig_20160428_743767f41e63f91cd5d065caa2a483af {
  meta:
    description = "datamaliciousorder - file 20160428_743767f41e63f91cd5d065caa2a483af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636b4d5812ce98c553f3e6f5577d03e985c0b7933eb569fb40e62669fcfb66ca"

  strings:
    $s1  = "while (ZMeUGA < bBAwxRn - (5537, 2023, 5492, 2846, 4884, 3585, 3051, 2919, 360, 2)) {" fullword ascii
    $s2  = "var saspYySA = String;" fullword ascii
    $s3  = "return nxau + EKj + Yrhmhhzy + lxuAuxc + zXiB + wYjQ;" fullword ascii
    $s4  = "if (4 === false) {" fullword ascii
    $s5  = "if (6 == false) {" fullword ascii
    $s6  = "if (7 == false) {" fullword ascii
    $s7  = "if (xhqd == false) {" fullword ascii
    $s8  = "if (HkxpPJQ === false) {" fullword ascii
    $s9  = "var LrUR = true;;" fullword ascii
    $s10 = "return dgGq;" fullword ascii
    $s11 = "function eGhGrnK(lfdd, lgldr, kfkm) {" fullword ascii
    $s12 = "var fRFdnMn = false;;" fullword ascii
    $s13 = "function MWwJ() {" fullword ascii
    $s14 = "var QBZFKHt = true;" fullword ascii
    $s15 = "function XzggZW(GWLz, VeYTRgv) {" fullword ascii
    $s16 = "var XRNW = false;" fullword ascii
    $s17 = "if (lpUo == false) {" fullword ascii
    $s18 = "return eNYIccOJ;" fullword ascii
    $s19 = "function wmnU() {" fullword ascii
    $s20 = "ZrWlOxZ(false);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}