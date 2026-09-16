rule sig_20160514_fe600f2be7350eab608b7d6e3ec3f1f0 {
  meta:
    description = "datamaliciousorder - file 20160514_fe600f2be7350eab608b7d6e3ec3f1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4655f8be272e4db1fdb87f655826d74aeb0dc72f93360bafd01e3f10cec33668"

  strings:
    $s1  = "while (HDIBa < ONkwCaYY - (8590 - 8588)) {" fullword ascii
    $s2  = "function noo() {" fullword ascii
    $s3  = "function sxJBc() {" fullword ascii
    $s4  = "return WuDfttdj;" fullword ascii
    $s5  = "return NBhTVA;" fullword ascii
    $s6  = "return BytD[idc];" fullword ascii
    $s7  = "return TFKkK;" fullword ascii
    $s8  = "function mUPLa(tuiyo, fmmd, kemn) {" fullword ascii
    $s9  = "function Vlyf() {" fullword ascii
    $s10 = "return VkGzxBo;" fullword ascii
    $s11 = "return DAawMVV;" fullword ascii
    $s12 = "function aMIGnkE() {" fullword ascii
    $s13 = "function gOznbMd(dfegg) {" fullword ascii
    $s14 = "function gmLen(Vyb) {" fullword ascii
    $s15 = "function WTT() {" fullword ascii
    $s16 = "function MMwsZG() {" fullword ascii
    $s17 = "return nnfkto;" fullword ascii
    $s18 = "function yaZUVz(vZLqxM, fqcBbr) {" fullword ascii
    $s19 = "function DPBQe() {" fullword ascii
    $s20 = "function bbZXoEa() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}