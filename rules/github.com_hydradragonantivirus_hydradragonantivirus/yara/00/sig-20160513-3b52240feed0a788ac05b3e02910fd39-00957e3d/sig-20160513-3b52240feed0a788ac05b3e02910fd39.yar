rule sig_20160513_3b52240feed0a788ac05b3e02910fd39 {
  meta:
    description = "datamaliciousorder - file 20160513_3b52240feed0a788ac05b3e02910fd39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09484fc1d69fb3891538ba319eb97b09175e8b61473de578873fc52220e6efb2"

  strings:
    $s1  = "while (JroimK < NzFrAOks - (453 + 1092 - 1543)) {" fullword ascii
    $s2  = "function qal() {" fullword ascii
    $s3  = "return njhJysxU;" fullword ascii
    $s4  = "function DNhH() {" fullword ascii
    $s5  = "function STGiJ(dfegg) {" fullword ascii
    $s6  = "return tTObobcS;" fullword ascii
    $s7  = "function jyAkloV() {" fullword ascii
    $s8  = "function inVCTl() {" fullword ascii
    $s9  = "return IGJgor;" fullword ascii
    $s10 = "function NKgFcW() {" fullword ascii
    $s11 = "return DAySS;" fullword ascii
    $s12 = "return MctGQuUS;" fullword ascii
    $s13 = "function oacBsvC(LvC, UbhYf) {" fullword ascii
    $s14 = "return NTzUw;" fullword ascii
    $s15 = "function AHRKb() {" fullword ascii
    $s16 = "function kOtaXS() {" fullword ascii
    $s17 = "mnWZrx = true;" fullword ascii
    $s18 = "return axVHunb;" fullword ascii
    $s19 = "function zewgm(rtwjdld, kdkndmd) {" fullword ascii
    $s20 = "function apE(tuiyo, fmmd, kemn) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}