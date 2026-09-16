rule sig_20160514_f23cdb3b8d4d6ab86c5c5b42f3068e3d {
  meta:
    description = "datamaliciousorder - file 20160514_f23cdb3b8d4d6ab86c5c5b42f3068e3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07e8bfc7aef2e603f208340b26ceb9746e8778ef0cf010c7edb00fe872bc5528"

  strings:
    $s1  = "while (hhvbmH < inXWlqVK - (4109 + 2142 - 6249)) {" fullword ascii
    $s2  = "function mxsQjl() {" fullword ascii
    $s3  = "function eUd() {" fullword ascii
    $s4  = "return mUUmu;" fullword ascii
    $s5  = "return QKXDujl;" fullword ascii
    $s6  = "function TWOQnRC(rtwjdld, kdkndmd) {" fullword ascii
    $s7  = "function dsFRN() {" fullword ascii
    $s8  = "if (XYGu === true) {" fullword ascii
    $s9  = "return klRcSD;" fullword ascii
    $s10 = "function rbow() {" fullword ascii
    $s11 = "function CzT(JghgGlr) {" fullword ascii
    $s12 = "function swWUWUR() {" fullword ascii
    $s13 = "function LGYyhp(Ljy) {" fullword ascii
    $s14 = "function NBiyJEH() {" fullword ascii
    $s15 = "function tmyaR(ainta) {" fullword ascii
    $s16 = "function SoJUUX() {" fullword ascii
    $s17 = "return sRBtpf;" fullword ascii
    $s18 = "function RoHLJ() {" fullword ascii
    $s19 = "return Cxpg;" fullword ascii
    $s20 = "fBOFD = true;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}