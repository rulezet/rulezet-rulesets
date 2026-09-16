rule sig_20160514_f8e67ce2d238e2d3c625b8ba85211d72 {
  meta:
    description = "datamaliciousorder - file 20160514_f8e67ce2d238e2d3c625b8ba85211d72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46eba64517397d65f66b7914a25fcc0274da8128fe4f637b77602451f58d33f1"

  strings:
    $s1  = "while (JqfdgCq < CGQpMxBg - (1303 - 1301)) {" fullword ascii
    $s2  = "return HxNTwaN;" fullword ascii
    $s3  = "return HCJFV;" fullword ascii
    $s4  = "function Vupn() {" fullword ascii
    $s5  = "return SxvB;" fullword ascii
    $s6  = "function FbjcsUl() {" fullword ascii
    $s7  = "return FoRxL;" fullword ascii
    $s8  = "function IoeLZ(apAyY) {" fullword ascii
    $s9  = "return ssWA[alGqy];" fullword ascii
    $s10 = "return zzfXHx;" fullword ascii
    $s11 = "return eOzMmalZ;" fullword ascii
    $s12 = "return nzDeJ;" fullword ascii
    $s13 = "function CjW() {" fullword ascii
    $s14 = "return ZrmDB;" fullword ascii
    $s15 = "function yns(rIrm) {" fullword ascii
    $s16 = "function bKLbz(tuiyo, fmmd, kemn) {" fullword ascii
    $s17 = "return QwnUk;" fullword ascii
    $s18 = "return CvDDJe;" fullword ascii
    $s19 = "return UJGyn;" fullword ascii
    $s20 = "return OajmL;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}