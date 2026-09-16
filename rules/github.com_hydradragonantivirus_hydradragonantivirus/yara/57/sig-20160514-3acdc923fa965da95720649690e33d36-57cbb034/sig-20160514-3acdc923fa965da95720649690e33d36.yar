rule sig_20160514_3acdc923fa965da95720649690e33d36 {
  meta:
    description = "datamaliciousorder - file 20160514_3acdc923fa965da95720649690e33d36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96fb38a03e0b5a1d59bc92b881ec9fedd5ee5fa0e49dbd65cdd4113b7bd00bb6"

  strings:
    $s1  = "while (kYDv < cmgCeJ - (2762 - 2760)) {" fullword ascii
    $s2  = "function GHbCmDT(WudC) {" fullword ascii
    $s3  = "return bjpaSSZA;" fullword ascii
    $s4  = "function wCOm(dfegg) {" fullword ascii
    $s5  = "return nukjW;" fullword ascii
    $s6  = "function imHV() {" fullword ascii
    $s7  = "function ZLfVFC() {" fullword ascii
    $s8  = "function JUK() {" fullword ascii
    $s9  = "function CrMYb() {" fullword ascii
    $s10 = "keCW(true, 220, \"yzIt\", false);" fullword ascii
    $s11 = "function EnN(ngDCMxQ) {" fullword ascii
    $s12 = "return YaiNAH;" fullword ascii
    $s13 = "return eNzfAYv;" fullword ascii
    $s14 = "function MYw() {" fullword ascii
    $s15 = "return ZJCYI;" fullword ascii
    $s16 = "return SlTd;" fullword ascii
    $s17 = "return Hhja;" fullword ascii
    $s18 = "return Dnnk;" fullword ascii
    $s19 = "return SqcxpdF;" fullword ascii
    $s20 = "function iJQXLBP() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}