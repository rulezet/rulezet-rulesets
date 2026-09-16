rule sig_20160514_387f3ac5de35e11a508e3b8b3fc214c5 {
  meta:
    description = "datamaliciousorder - file 20160514_387f3ac5de35e11a508e3b8b3fc214c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c302f33de89e63e68a17ad8db448b3c96eaa3ebd95cb80e1a45b5ca0193bc42"

  strings:
    $s1  = "while (WYks < hwLI - (789 + 1433 - 2220)) {" fullword ascii
    $s2  = "return UZZFoqvX;" fullword ascii
    $s3  = "function XYSYtw() {" fullword ascii
    $s4  = "return TSjTRXs;" fullword ascii
    $s5  = "return pLSgP;" fullword ascii
    $s6  = "function OegHP() {" fullword ascii
    $s7  = "return rohZM;" fullword ascii
    $s8  = "function GINke(AxZ, ZuHIS) {" fullword ascii
    $s9  = "AWsf = true;" fullword ascii
    $s10 = "return YljrcHkW;" fullword ascii
    $s11 = "function WlPc(cszS) {" fullword ascii
    $s12 = "return enZcO;" fullword ascii
    $s13 = "function WIDO() {" fullword ascii
    $s14 = "var WtAT = String;" fullword ascii
    $s15 = "return kCWAXUw;" fullword ascii
    $s16 = "return GxRBI;" fullword ascii
    $s17 = "return whCJE;" fullword ascii
    $s18 = "return OxpNsMU;" fullword ascii
    $s19 = "return JKhE;" fullword ascii
    $s20 = "function GkS(jBD) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}