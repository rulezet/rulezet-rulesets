rule _20160901_258d0262795c2160624a2e8ce87ac4cc_20160901_bf8b512fa2d4_185 {
  meta:
    description = "datamaliciousorder - from files 20160901_258d0262795c2160624a2e8ce87ac4cc.js, 20160901_bf8b512fa2d43aaa3b1b9edee96a03de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dc29f9b4df160f3e43085fa3bb432beb855733bf16bc5775110e446bcb066d8"
    hash2       = "002b592519d36fd2acdf154a6c8f7db28ab287f467de4860a9073f66bf1b0d5d"

  strings:
    $s1  = "while (mXLPNVy < AeaDooDj - 2) {" fullword ascii
    $s2  = "var KldgDCze = new Array(UFqkk + \"r\" + MYpytQgH);" fullword ascii
    $s3  = "function uFL(Rprk, Ktn) {" fullword ascii
    $s4  = "return Lucd;" fullword ascii
    $s5  = "return cOlH;" fullword ascii
    $s6  = "return ollO;" fullword ascii
    $s7  = "function uAHnvN() {" fullword ascii
    $s8  = "return sIwQ;" fullword ascii
    $s9  = "function diUbZ() {" fullword ascii
    $s10 = "function xuWu() {" fullword ascii
    $s11 = "function eqFHzbg(OvkKTTY) {" fullword ascii
    $s12 = "function PbBCH(rtwjdld, kdkndmd) {" fullword ascii
    $s13 = "return fLSsj;" fullword ascii
    $s14 = "return wgkyf;" fullword ascii
    $s15 = "return QjICyM;" fullword ascii
    $s16 = "return MpdE;" fullword ascii
    $s17 = "return SlLJGbzP;" fullword ascii
    $s18 = "return spsPQF;" fullword ascii
    $s19 = "return axLRdWnj;" fullword ascii
    $s20 = "function rytBy(ipVjaow) {" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}