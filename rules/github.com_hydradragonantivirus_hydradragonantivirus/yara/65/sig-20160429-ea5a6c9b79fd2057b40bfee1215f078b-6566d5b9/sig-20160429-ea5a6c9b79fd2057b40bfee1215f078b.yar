rule sig_20160429_ea5a6c9b79fd2057b40bfee1215f078b {
  meta:
    description = "datamaliciousorder - file 20160429_ea5a6c9b79fd2057b40bfee1215f078b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc14bbbe795a93cb0df4c0cdce0694efe79c44789f449ee220ec8bf6ed823ce1"

  strings:
    $s1  = "while (DJYK < ciL - (4904, 4061, 7882, 2653, 3569, 3693, 6261, 4432, 7674, 4893, 2)) {" fullword ascii
    $s2  = "return GzFQoBQq + mbuvW + NYtS + hTGIF + BDr + vYYbO;" fullword ascii
    $s3  = "return ZmuSErbi;" fullword ascii
    $s4  = "if (2 == false) {" fullword ascii
    $s5  = "if (7 === false) {" fullword ascii
    $s6  = "Rsn[kxdNu(\"002037011047\")](FFxmF, fglxFEsX, false);" fullword ascii
    $s7  = "var QryC = false;" fullword ascii
    $s8  = "return thGYzIg;" fullword ascii
    $s9  = "function PXUhHtt() {" fullword ascii
    $s10 = "function cTHZL() {" fullword ascii
    $s11 = "var TvRKsbj = true;" fullword ascii
    $s12 = "function MkyZ() {" fullword ascii
    $s13 = "var mLAUlg = true;" fullword ascii
    $s14 = "if (AFXFPr === false) {" fullword ascii
    $s15 = "if (sztbyzs(0, 497, 0, false) == true) {" fullword ascii
    $s16 = "function UkDo(twVbOXE) {" fullword ascii
    $s17 = "var VOtT = false;" fullword ascii
    $s18 = "return GeZyGVEC;" fullword ascii
    $s19 = "var bOLM = false;" fullword ascii
    $s20 = "return ddOcwxOq;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}