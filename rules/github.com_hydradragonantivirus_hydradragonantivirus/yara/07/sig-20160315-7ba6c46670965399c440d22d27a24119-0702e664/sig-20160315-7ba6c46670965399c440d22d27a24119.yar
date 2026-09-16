rule sig_20160315_7ba6c46670965399c440d22d27a24119 {
  meta:
    description = "datamaliciousorder - file 20160315_7ba6c46670965399c440d22d27a24119.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be40dd204591560a8242c27ed154eddcefc99367a39d253df4d28d238767391e"

  strings:
    $s1  = "return evJHGnv[0] + evJHGnv[2] + evJHGnv[4] + \".F\" + evJHGnv[7] + evJHGnv[9] + evJHGnv[12] + evJHGnv[14];" fullword ascii
    $s2  = "var UJ = true  , VKOb = CfX[7] + CfX[9] + CfX[11];" fullword ascii
    $s3  = "var CfX = (\"2.XMLHTTP EDHhSxN NUmmM XML ream St sQbzChhR AD dYEMFNE O nsvx D\").split(\" \");" fullword ascii
    $s4  = "var evJHGnv = bEcWU(\"Sc BgMVBqk r BPhvbwjIK ipting HRYuryD ZTI ile qxTurXhOSEErAi System Ot uRzzL Obj NOIwAF ect haScvtk KClvF" ascii
    $s5  = "kDkPr.open(XosPs,aBCKA,false);" fullword ascii
    $s6  = "var evJHGnv = bEcWU(\"Sc BgMVBqk r BPhvbwjIK ipting HRYuryD ZTI ile qxTurXhOSEErAi System Ot uRzzL Obj NOIwAF ect haScvtk KClvF" ascii
    $s7  = "function eict(MjlAg) {" fullword ascii
    $s8  = "return mWCpu;" fullword ascii
    $s9  = "function GnLd(ihDbv) {" fullword ascii
    $s10 = "function jLmFxPjJV(IJpEH) {" fullword ascii
    $s11 = "function NBjZZvyf(btq) {" fullword ascii
    $s12 = "function UFJdMFJkx(qXFYIxVojws) {" fullword ascii
    $s13 = "if (emsls == 686-486){return true;} else {return false;}" fullword ascii
    $s14 = "return LjDxft.position=179-179;" fullword ascii
    $s15 = "function coHTVTH(ACyk,bupBS) {" fullword ascii
    $s16 = "function aSOv(cRaLX) {" fullword ascii
    $s17 = "return bzMd.responseBody;" fullword ascii
    $s18 = "function xHMM(kDkPr,aBCKA,XosPs) {" fullword ascii
    $s19 = "return sMciOaT" fullword ascii
    $s20 = "return hNq.split(fMqed);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}