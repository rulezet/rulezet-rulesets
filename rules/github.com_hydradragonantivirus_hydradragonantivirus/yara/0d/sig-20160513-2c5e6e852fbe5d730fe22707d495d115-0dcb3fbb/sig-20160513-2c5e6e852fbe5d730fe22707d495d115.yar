rule sig_20160513_2c5e6e852fbe5d730fe22707d495d115 {
  meta:
    description = "datamaliciousorder - file 20160513_2c5e6e852fbe5d730fe22707d495d115.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0da88dbe722a72ed855e66972e03f7c225f71ae3b49fd760c19346d234bdf51"

  strings:
    $s1  = "while (oMxnKSRr < wrsh - (6358 + 1647 - 8003)) {" fullword ascii
    $s2  = "function GFA(dfegg) {" fullword ascii
    $s3  = "function IrpM() {" fullword ascii
    $s4  = "function sxHxN() {" fullword ascii
    $s5  = "function GBn() {" fullword ascii
    $s6  = "function Swo() {" fullword ascii
    $s7  = "FrKn = true;" fullword ascii
    $s8  = "function Kbv() {" fullword ascii
    $s9  = "return RPCBQD;" fullword ascii
    $s10 = "function PGsDfEl() {" fullword ascii
    $s11 = "function PeornQD(dZVjcPQO) {" fullword ascii
    $s12 = "function CPzp() {" fullword ascii
    $s13 = "function rBmKZl(rtwjdld, kdkndmd) {" fullword ascii
    $s14 = "function gxqvv() {" fullword ascii
    $s15 = "return NZJabNIu[WEcuTlWA];" fullword ascii
    $s16 = "return egGlEoj;" fullword ascii
    $s17 = "function MGLCndf(WEcuTlWA) {" fullword ascii
    $s18 = "return TisX;" fullword ascii
    $s19 = "function nPOCO(XLIyS) {" fullword ascii
    $s20 = "return aUZhbV;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}