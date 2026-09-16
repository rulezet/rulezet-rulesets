rule sig_20160419_41c7affbcb89edb08701fc12131821df {
  meta:
    description = "datamaliciousorder - file 20160419_41c7affbcb89edb08701fc12131821df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "981ce8b6e2f4b42a5b1335f4cc3fa88e4558a70963ef09d64500a0fdc8c06655"

  strings:
    $s1  = "while (xtqtaPV < YcDVAK - (7200, 779, 9396, 4426, 3299, 2898, 8236, 3054, 1617, 9166, 4155, 2)) {" fullword ascii
    $s2  = "return WScript;" fullword ascii
    $s3  = "return zbLQLUa + ka + WjjbpH + sFrnOKj;" fullword ascii
    $s4  = "switch (\"0\") {" fullword ascii
    $s5  = "if (6 == false) {" fullword ascii
    $s6  = "var IpHwQH = true;" fullword ascii
    $s7  = "var GDRPORH = true;" fullword ascii
    $s8  = "var FcwVZ = false;" fullword ascii
    $s9  = "function yEcSePt(FFBV) {" fullword ascii
    $s10 = "nUH[LjCff(\"041049046010\")](bkE, JWynyDG, false);" fullword ascii
    $s11 = "function mCf() {" fullword ascii
    $s12 = "switch (12624) {" fullword ascii
    $s13 = "if (mUiDVt(\"1\") == false) {" fullword ascii
    $s14 = "return PuZcjK;" fullword ascii
    $s15 = "return BmT;" fullword ascii
    $s16 = "if (gLVr === false) {" fullword ascii
    $s17 = "var VxlnuMO = false;" fullword ascii
    $s18 = "var fKCVKG = true;" fullword ascii
    $s19 = "if (1 == false) {" fullword ascii
    $s20 = "var HuBny = false;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}