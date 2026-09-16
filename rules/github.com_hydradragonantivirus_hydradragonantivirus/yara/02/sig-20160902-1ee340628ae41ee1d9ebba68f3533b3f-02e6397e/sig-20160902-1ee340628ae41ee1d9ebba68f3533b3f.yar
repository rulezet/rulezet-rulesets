rule sig_20160902_1ee340628ae41ee1d9ebba68f3533b3f {
  meta:
    description = "datamaliciousorder - file 20160902_1ee340628ae41ee1d9ebba68f3533b3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3464a9ee0c4360afa7c58f77ac05a8d762ef0ed4524b3d75fe2d5e580629431a"

  strings:
    $s1  = "while (QvkldbgC < OwJfN - 2) {" fullword ascii
    $s2  = "var PunCdCU = new Array(SgCwm + \"r\" + SjwCRFC);" fullword ascii
    $s3  = "function YPMCW(rtwjdld, kdkndmd) {" fullword ascii
    $s4  = "function OnYsT() {" fullword ascii
    $s5  = "return bcve;" fullword ascii
    $s6  = "function Efgs() {" fullword ascii
    $s7  = "var oKydZNg = String;" fullword ascii
    $s8  = "function mFpq(str) {" fullword ascii
    $s9  = "return PclapIU;" fullword ascii
    $s10 = "return TCpik;" fullword ascii
    $s11 = "function sxBe(NfZDp) {" fullword ascii
    $s12 = "return AOFNMYGq;" fullword ascii
    $s13 = "return VKsUCzQr;" fullword ascii
    $s14 = "return zZRgV;" fullword ascii
    $s15 = "return RfvQ;" fullword ascii
    $s16 = "return uyaNVZ;" fullword ascii
    $s17 = "return dZfdXO;" fullword ascii
    $s18 = "function ENI(XlrgCF) {" fullword ascii
    $s19 = "return qeSpQGK;" fullword ascii
    $s20 = "function vCNkrcV() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}