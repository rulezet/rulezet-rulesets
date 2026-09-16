rule sig_20160514_53ac630539e55f96c3d9a781e370595b {
  meta:
    description = "datamaliciousorder - file 20160514_53ac630539e55f96c3d9a781e370595b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c624cf29e0c562ab84ff61054d941385a423b40e776cec9c6003e594fd823bb"

  strings:
    $s1  = "while (PXnVK < IXQWKpjV - (5254 - 5252)) {" fullword ascii
    $s2  = "return WAtrJvQR;" fullword ascii
    $s3  = "function CcXYWC(QkxFO) {" fullword ascii
    $s4  = "function VTkt(dNalml, qeTSQDA) {" fullword ascii
    $s5  = "return xrqTUpV;" fullword ascii
    $s6  = "return lSfIZC;" fullword ascii
    $s7  = "function znbpoY() {" fullword ascii
    $s8  = "function FZGzbYf(dfegg) {" fullword ascii
    $s9  = "function YJx(tuiyo, fmmd, kemn) {" fullword ascii
    $s10 = "return EikD;" fullword ascii
    $s11 = "function LiGFG(pGHvqEN, jkBjsocY) {" fullword ascii
    $s12 = "function xwzEd() {" fullword ascii
    $s13 = "return IvunAn;" fullword ascii
    $s14 = "function bhTSk() {" fullword ascii
    $s15 = "var goQo = true;" fullword ascii
    $s16 = "return rAnXZZ;" fullword ascii
    $s17 = "function lAgrlGE() {" fullword ascii
    $s18 = "return mSnMzm;" fullword ascii
    $s19 = "if (ETNh(1, false, true) == 0) {" fullword ascii
    $s20 = "return dUOqTFfS;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}