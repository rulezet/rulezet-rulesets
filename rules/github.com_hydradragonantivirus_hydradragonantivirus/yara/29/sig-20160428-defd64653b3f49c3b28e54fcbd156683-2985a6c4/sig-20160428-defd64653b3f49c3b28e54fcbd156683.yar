rule sig_20160428_defd64653b3f49c3b28e54fcbd156683 {
  meta:
    description = "datamaliciousorder - file 20160428_defd64653b3f49c3b28e54fcbd156683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e5b6a1cd36927273766b9c7f5ceb3dc70b6321f93e39f58f5aba0c159afc960"

  strings:
    $s1  = "while (cWWWC < DXEzGYHl - (6707, 9064, 922, 3954, 2907, 4576, 2)) {" fullword ascii
    $s2  = "sDMV = pony('' + Blt + '');" fullword ascii
    $s3  = "return blozlcda + GtZpygr + mCVrDK + bDAZ + WWph + PsnT;" fullword ascii
    $s4  = "if (1 === false) {" fullword ascii
    $s5  = "if (3 == false) {" fullword ascii
    $s6  = "if (2 == false) {" fullword ascii
    $s7  = "function PVqkggC(JpyNy) {" fullword ascii
    $s8  = "var xlRvLRY = false;" fullword ascii
    $s9  = "if (NKZ == false) {" fullword ascii
    $s10 = "var SdFkPkE = String;" fullword ascii
    $s11 = "return UGlFIl;" fullword ascii
    $s12 = "return sER;" fullword ascii
    $s13 = "function ThHVnw(dfegg) {" fullword ascii
    $s14 = "switch (\"tXBBrBJ\") {" fullword ascii
    $s15 = "function JyBJtg(qqjAIC, GoovJt) {" fullword ascii
    $s16 = "return TpYJv;" fullword ascii
    $s17 = "var eVcHsmZ = true;;" fullword ascii
    $s18 = "return wimGAdO;" fullword ascii
    $s19 = "return daP;" fullword ascii
    $s20 = "function jGqzPS() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}