rule sig_20160411_5f2bec9b064e5fc7d417d2111e150795 {
  meta:
    description = "datamaliciousorder - file 20160411_5f2bec9b064e5fc7d417d2111e150795.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3f53882f9ed417f980fb1ba848a738275e58a24e83c09fe5427106336e795b0"

  strings:
    $s1  = "var bH = true  , MZbQ = wKg[7] + wKg[9] + wKg[11];" fullword ascii
    $s2  = "return NMEgxGg[0] + NMEgxGg[2] + NMEgxGg[4] + \".F\" + NMEgxGg[7] + NMEgxGg[9] + NMEgxGg[12] + NMEgxGg[14];" fullword ascii
    $s3  = "var wKg = (\"2.XMLHTTP LcJdbwm wqPSP XML ream St nUKgZDUt AD jLzKYIY O eMQC D\").split(\" \");" fullword ascii
    $s4  = "pDSh.open(BByUb,cURKj,false);" fullword ascii
    $s5  = "function cqnb(LGvRT) {" fullword ascii
    $s6  = "if(K>=a.length) {break;}" fullword ascii
    $s7  = "if (LGvRT > 163862-699){return true;} else {return false;}" fullword ascii
    $s8  = "return udeULCp;" fullword ascii
    $s9  = "VQN = K; break; " fullword ascii
    $s10 = "function GtHOvh(XDnddVL) {" fullword ascii
    $s11 = "return DWJYBlL[0];" fullword ascii
    $s12 = "function RcYxkfe(btRw) {" fullword ascii
    $s13 = "if (J >= xgNWm.length) {break;}" fullword ascii
    $s14 = "function wwksF(NZwDUH) {" fullword ascii
    $s15 = "function dggd(xgNWm) {" fullword ascii
    $s16 = "return EYWlc.status;" fullword ascii
    $s17 = "function sImPzems(OmST) {" fullword ascii
    $s18 = "return uVGUGLx(Ky,kxaouD+hRrxB[457-449]);" fullword ascii
    $s19 = "function hmAV(EYWlc) {" fullword ascii
    $s20 = "function oWOmtsSIK(xmnkp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}