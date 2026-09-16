rule sig_20160428_f651a4e853267759edf2b14ea7c17c25 {
  meta:
    description = "datamaliciousorder - file 20160428_f651a4e853267759edf2b14ea7c17c25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bb9d2ee50c6078c933cea5571b72c18b503d53e10d457f8da186388a9fdea99"

  strings:
    $s1  = "while (HTv < FgKVjUFm - (2990, 7248, 8678, 8484, 462, 4408, 7220, 2)) {" fullword ascii
    $s2  = "return RxWRTpOC + nbZU + kMBf + VPpRw + lyx + tscR;" fullword ascii
    $s3  = "if (2 === true) {" fullword ascii
    $s4  = "if (6 == false) {" fullword ascii
    $s5  = "if (3 === true) {" fullword ascii
    $s6  = "if (2 == false) {" fullword ascii
    $s7  = "if (6 === true) {" fullword ascii
    $s8  = "if (7 === false) {" fullword ascii
    $s9  = "return pQWmXRft[OMuXn];" fullword ascii
    $s10 = "var xqXtW = false;" fullword ascii
    $s11 = "function hZYBqrm(hYlPzDej, FOkhF) {" fullword ascii
    $s12 = "var moUEYhk = true;" fullword ascii
    $s13 = "lfdd[lHBiTsW(\"061001008035\")](lgldr, kfkm, false);" fullword ascii
    $s14 = "function PZimacC() {" fullword ascii
    $s15 = "var rawEp = false;" fullword ascii
    $s16 = "var zibs = false;" fullword ascii
    $s17 = "return AZIUGy;" fullword ascii
    $s18 = "var dIBtRHK = false;" fullword ascii
    $s19 = "function Ydi(pNSAGo, sJnF) {" fullword ascii
    $s20 = "function fhC(bLui, ZyeS) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}