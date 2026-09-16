rule sig_20160429_b34586de487b48230f0a8331c1683a69 {
  meta:
    description = "datamaliciousorder - file 20160429_b34586de487b48230f0a8331c1683a69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83bf4ffce3533fa893349f928adde6b6cc3b3ab0d62323015ab1d9dfc119f3a5"

  strings:
    $s1  = "while (FBGLZby < KNSPglHh - (5122, 3547, 9528, 4705, 4454, 1533, 8774, 1499, 2711, 2432, 8591, 973, 2)) {" fullword ascii
    $s2  = "return KbHQVr + yVR + Eiasj + TOSDxz + VIrUTS + EThuPz;" fullword ascii
    $s3  = "if (4 === false) {" fullword ascii
    $s4  = "if (3 == true) {" fullword ascii
    $s5  = "if (5 === true) {" fullword ascii
    $s6  = "if (1 == false) {" fullword ascii
    $s7  = "if (7 == false) {" fullword ascii
    $s8  = "if (1 == true) {" fullword ascii
    $s9  = "if (4 == false) {" fullword ascii
    $s10 = "if (4 === true) {" fullword ascii
    $s11 = "var juPhj = String;" fullword ascii
    $s12 = "var FCLkg = true;" fullword ascii
    $s13 = "return SDvfBEf;" fullword ascii
    $s14 = "function PTzljY() {" fullword ascii
    $s15 = "return KeFboS;" fullword ascii
    $s16 = "var fIKpjt = true;" fullword ascii
    $s17 = "var IXcgrJ = false;" fullword ascii
    $s18 = "function mCpiaB(NJBQBbwJ) {" fullword ascii
    $s19 = "function bvC(qjAGgst) {" fullword ascii
    $s20 = "return GrXzvK[iyqkxFVX];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}