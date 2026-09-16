rule sig_20160428_3d56c78abdcf21310972a67fab2f6927 {
  meta:
    description = "datamaliciousorder - file 20160428_3d56c78abdcf21310972a67fab2f6927.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "911b68db9f0ad6c04f0b78b18a91bdb3adf4ff68a887a85b1700d64ad7cfdcf4"

  strings:
    $s1  = "while (lmLL < WkqY - (3897, 220, 6641, 2)) {" fullword ascii
    $s2  = "return GlkOzrPD + bNy + qDgqWuE + IMhwbu + cfDIqOw + fltlngJ;" fullword ascii
    $s3  = "if (1 === false) {" fullword ascii
    $s4  = "if (1 == false) {" fullword ascii
    $s5  = "if (5 == false) {" fullword ascii
    $s6  = "if (2 == true) {" fullword ascii
    $s7  = "return iBV;" fullword ascii
    $s8  = "function PAqevb(zmgTQxf) {" fullword ascii
    $s9  = "function ttd() {" fullword ascii
    $s10 = "if (eNVsmt === true) {" fullword ascii
    $s11 = "var hMsSA = true;" fullword ascii
    $s12 = "function kmiqdzf(Plhu, NJSHuNxk) {" fullword ascii
    $s13 = "var KwlXSs = false;" fullword ascii
    $s14 = "return ePAtTPFT[(81, 9160, 7067, 7690, 5490, 6)];" fullword ascii
    $s15 = "return NonpbK;" fullword ascii
    $s16 = "function nNFdnVh() {" fullword ascii
    $s17 = "var VAGDV = false;" fullword ascii
    $s18 = "function rNw() {" fullword ascii
    $s19 = "return Asioha;" fullword ascii
    $s20 = "function Sxx() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}