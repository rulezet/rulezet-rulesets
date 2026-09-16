rule sig_20160514_88b17703286d4510536877d0964f1432 {
  meta:
    description = "datamaliciousorder - file 20160514_88b17703286d4510536877d0964f1432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2caa9ac453d3783489c85eada4af1b3a6f958b3c8b49d915f1fb3ee49113a140"

  strings:
    $s1  = "while (MuLy < RcUPQAE - (1133 - 1131)) {" fullword ascii
    $s2  = "function LbjClmB(CZxvrWn) {" fullword ascii
    $s3  = "return anOETbl;" fullword ascii
    $s4  = "return ojZhv;" fullword ascii
    $s5  = "return pIOQB;" fullword ascii
    $s6  = "function NUevIV() {" fullword ascii
    $s7  = "return XCpleQh;" fullword ascii
    $s8  = "return UYKO;" fullword ascii
    $s9  = "return QthPEmL;" fullword ascii
    $s10 = "var qRLOOXy = true;" fullword ascii
    $s11 = "return ZTqXDOAi;" fullword ascii
    $s12 = "function FAfNgh(ORjPCTtH) {" fullword ascii
    $s13 = "function fGrkw() {" fullword ascii
    $s14 = "function jcja(fWZZ) {" fullword ascii
    $s15 = "return sQnaCYFn;" fullword ascii
    $s16 = "return DidzHM;" fullword ascii
    $s17 = "return ROYbOYAS;" fullword ascii
    $s18 = "function ePnQlqk(HaMQwB) {" fullword ascii
    $s19 = "function OhVIL() {" fullword ascii
    $s20 = "function Wvd(XjLRUOGw, EroKhUd) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}