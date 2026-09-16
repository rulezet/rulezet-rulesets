rule sig_20160428_9328c769bd89033aea2a29695d71324e {
  meta:
    description = "datamaliciousorder - file 20160428_9328c769bd89033aea2a29695d71324e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dc06f79c609a7afa78b0220c05348340165151052cfe6a55f954d1734354559"

  strings:
    $s1  = "while (DTARv < JEG - (9255, 4456, 2514, 5313, 7377, 2251, 2)) {" fullword ascii
    $s2  = "return UJStgx + TQFFZBj + GBgYrO + csD + aMTzr + jkhqHQj;" fullword ascii
    $s3  = "if (6 === false) {" fullword ascii
    $s4  = "if (3 === true) {" fullword ascii
    $s5  = "if (1 == true) {" fullword ascii
    $s6  = "if (5 === false) {" fullword ascii
    $s7  = "var VHFc = true;" fullword ascii
    $s8  = "function aAuvDS() {" fullword ascii
    $s9  = "function lUraJt() {" fullword ascii
    $s10 = "switch (yMy) {" fullword ascii
    $s11 = "function PnbpKn() {" fullword ascii
    $s12 = "return DypHiBz;" fullword ascii
    $s13 = "if (fONdaf === false) {" fullword ascii
    $s14 = "return iDKfAeg;" fullword ascii
    $s15 = "var rOaljf = true;" fullword ascii
    $s16 = "function CDKkO() {" fullword ascii
    $s17 = "var LxDTTMc = false;" fullword ascii
    $s18 = "function GGvMoP(Fkgq, hfO, uvlGM, KNMdO) {" fullword ascii
    $s19 = "return wOxXY;" fullword ascii
    $s20 = "GGvMoP(true, 17, 1, 1);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}