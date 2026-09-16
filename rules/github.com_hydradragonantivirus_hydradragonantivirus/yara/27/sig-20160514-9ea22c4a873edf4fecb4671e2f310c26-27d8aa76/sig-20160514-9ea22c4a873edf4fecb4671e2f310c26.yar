rule sig_20160514_9ea22c4a873edf4fecb4671e2f310c26 {
  meta:
    description = "datamaliciousorder - file 20160514_9ea22c4a873edf4fecb4671e2f310c26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "624523da25e3d13c5871fd60a22561d90b27d3d5bc68f53945b3fad58b8333d8"

  strings:
    $s1  = "while (XlksFr < nxoREpg - (6520 - 6518)) {" fullword ascii
    $s2  = "function CokNwY(HEHx, SwCbkFXJ) {" fullword ascii
    $s3  = "TCtcH = true;" fullword ascii
    $s4  = "var uupP = false;" fullword ascii
    $s5  = "return wjMB;" fullword ascii
    $s6  = "return sgHeBTKF;" fullword ascii
    $s7  = "return EyuE;" fullword ascii
    $s8  = "return WSkEM;" fullword ascii
    $s9  = "function YloBE() {" fullword ascii
    $s10 = "return Futhga;" fullword ascii
    $s11 = "function EnLFK(dfegg) {" fullword ascii
    $s12 = "return PDbdML;" fullword ascii
    $s13 = "return QOnrrd;" fullword ascii
    $s14 = "return tdcx;" fullword ascii
    $s15 = "return Mnbkxc;" fullword ascii
    $s16 = "return cdas;" fullword ascii
    $s17 = "function xRft() {" fullword ascii
    $s18 = "function MDkHp() {" fullword ascii
    $s19 = "function sTyQ(gLbt) {" fullword ascii
    $s20 = "function Vwfzi() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}