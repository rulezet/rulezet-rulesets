rule sig_20160419_fcd3644adda48d56d2e2699e8f786951 {
  meta:
    description = "datamaliciousorder - file 20160419_fcd3644adda48d56d2e2699e8f786951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad7f0a84114c9bc42fd70d16bcf2f6bfbf0d0b37e5c3e0406aad533764477240"

  strings:
    $s1  = "return RSTHULG[0] + RSTHULG[2] + RSTHULG[4] + \".F\" + RSTHULG[7] + RSTHULG[9] + RSTHULG[12] + RSTHULG[14];" fullword ascii
    $s2  = "var ids = odMV(BELT + \"B.\" + nHs[5]+(983398, nHs[4]));" fullword ascii
    $s3  = "var XI = true  , BELT = nHs[7] + nHs[9] + nHs[11];" fullword ascii
    $s4  = "PWbn.open(SrjFA,YJzAE,false);" fullword ascii
    $s5  = "var nHs = (\"2.XMLHTTP VViTsyJ DCvqB XML ream St ArlBZlkp AD dNDaZof O RvGM D\").split(\" \");" fullword ascii
    $s6  = "return GRspM.status;" fullword ascii
    $s7  = "function eAFS(RewJH) {" fullword ascii
    $s8  = "if (aJKAj > 177406-878){return true;} else {return false;}" fullword ascii
    $s9  = "function hLeh(tAnvy) {" fullword ascii
    $s10 = "function oHPaH(QScUSM) {" fullword ascii
    $s11 = "return uXP.size;" fullword ascii
    $s12 = "function gQPMBq(EHiD,grMfVv) {" fullword ascii
    $s13 = "function ZSDVaX(YolvqVv) {" fullword ascii
    $s14 = "function tbMQ(MEpDK,qiSBt) {" fullword ascii
    $s15 = "function ANRxAVR(IJPB,Olkeg) {" fullword ascii
    $s16 = "return KEUSG;" fullword ascii
    $s17 = "function qDkC(SUsrr,liRWe) {" fullword ascii
    $s18 = "hdq = L; break; " fullword ascii
    $s19 = "function WoJUo(uOAVHi) {" fullword ascii
    $s20 = "function yVMA(HaZoW,YJzAE,SrjFA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}