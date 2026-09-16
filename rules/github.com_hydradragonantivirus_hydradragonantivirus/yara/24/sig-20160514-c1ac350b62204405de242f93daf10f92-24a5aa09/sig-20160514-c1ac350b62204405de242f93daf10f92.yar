rule sig_20160514_c1ac350b62204405de242f93daf10f92 {
  meta:
    description = "datamaliciousorder - file 20160514_c1ac350b62204405de242f93daf10f92.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3454fd14ab8376a39accf1d9e6a22a2dc70fc67f65d7ea7d258122c71f37e6b"

  strings:
    $s1  = "while (qFvMlG < DYOAgn - (9085 + 2287 - 11370)) {" fullword ascii
    $s2  = "return nGCeT;" fullword ascii
    $s3  = "function JVMCH(rtwjdld, kdkndmd) {" fullword ascii
    $s4  = "function YsNj() {" fullword ascii
    $s5  = "function ixhzj(jnMDV) {" fullword ascii
    $s6  = "function LYzklA() {" fullword ascii
    $s7  = "return SgbqKd;" fullword ascii
    $s8  = "return qMaHxeFT;" fullword ascii
    $s9  = "function bdKzcV() {" fullword ascii
    $s10 = "return uJkj;" fullword ascii
    $s11 = "return UCeZlH;" fullword ascii
    $s12 = "return vkzEVBxG;" fullword ascii
    $s13 = "function oanBj() {" fullword ascii
    $s14 = "return KeJTY;" fullword ascii
    $s15 = "function VPYPMU() {" fullword ascii
    $s16 = "return xEcHLT;" fullword ascii
    $s17 = "var GNVEX = String;" fullword ascii
    $s18 = "function KqL(gCTEMTDe, sKUCy) {" fullword ascii
    $s19 = "return iUCMhK[tRijnKb];" fullword ascii
    $s20 = "return YsfE;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}