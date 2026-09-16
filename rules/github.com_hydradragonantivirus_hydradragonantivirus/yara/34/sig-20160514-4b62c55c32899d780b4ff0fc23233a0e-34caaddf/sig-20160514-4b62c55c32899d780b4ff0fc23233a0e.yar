rule sig_20160514_4b62c55c32899d780b4ff0fc23233a0e {
  meta:
    description = "datamaliciousorder - file 20160514_4b62c55c32899d780b4ff0fc23233a0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c365022d6aac26191f6454d85bcf115732fed4b6cd01d9962ffe48cb70aeb0ca"

  strings:
    $s1  = "while (zUeSbvb < yHoK - (8875 - 8873)) {" fullword ascii
    $s2  = "return xdSXVe[tDydWByc];" fullword ascii
    $s3  = "return kaNV;" fullword ascii
    $s4  = "function Xseq(tDydWByc) {" fullword ascii
    $s5  = "function SzIIC() {" fullword ascii
    $s6  = "function PkCfx(Klx) {" fullword ascii
    $s7  = "function Zqk() {" fullword ascii
    $s8  = "function oCjh() {" fullword ascii
    $s9  = "function UaqV(rsCBpWf, ZboxePJ) {" fullword ascii
    $s10 = "return Hxzuv;" fullword ascii
    $s11 = "return lXaeHx;" fullword ascii
    $s12 = "vkjMJZ(true, 1);" fullword ascii
    $s13 = "return FnIdy;" fullword ascii
    $s14 = "function pLQmP(dfegg) {" fullword ascii
    $s15 = "return WXYbDI;" fullword ascii
    $s16 = "return Omhht;" fullword ascii
    $s17 = "return KzUvqAR;" fullword ascii
    $s18 = "return JLjjsghr;" fullword ascii
    $s19 = "return WkBRl;" fullword ascii
    $s20 = "return vkLstaBQ;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}