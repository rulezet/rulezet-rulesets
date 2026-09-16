rule sig_20160429_bc9b883e834a8e992007cc5ba378dcd3 {
  meta:
    description = "datamaliciousorder - file 20160429_bc9b883e834a8e992007cc5ba378dcd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4a3af28a8f75bb0f68d1117900f729b52bc7a047ac485b98a0d911fed2b6ccb"

  strings:
    $s1  = "while (hoLAyfA < Cmvvq - (7447, 7057, 4307, 5194, 6343, 4159, 3456, 2)) {" fullword ascii
    $s2  = "return RlVr + tclpD + oMowKiJ + HtaHja + kNTE + LPW;" fullword ascii
    $s3  = "if (3 == true) {" fullword ascii
    $s4  = "if (6 == true) {" fullword ascii
    $s5  = "return xLT;" fullword ascii
    $s6  = "if (qHoME == false) {" fullword ascii
    $s7  = "var xVBd = false;" fullword ascii
    $s8  = "var RPuJ = false;" fullword ascii
    $s9  = "function Khhegji(TWEKno, VBqD) {" fullword ascii
    $s10 = "var QyOfEe = false;" fullword ascii
    $s11 = "return pOatjuZ;" fullword ascii
    $s12 = "if (MyaT === true) {" fullword ascii
    $s13 = "return UGRsvT[0];" fullword ascii
    $s14 = "var gqss = true;" fullword ascii
    $s15 = "var HoBEGW = true;" fullword ascii
    $s16 = "return lmpkDnlm;" fullword ascii
    $s17 = "switch (759) {" fullword ascii
    $s18 = "var aCPIZq = false;" fullword ascii
    $s19 = "lGiFTlN(1, \"WeBHeJm\", false, 1);" fullword ascii
    $s20 = "return bfkQRmvz;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}