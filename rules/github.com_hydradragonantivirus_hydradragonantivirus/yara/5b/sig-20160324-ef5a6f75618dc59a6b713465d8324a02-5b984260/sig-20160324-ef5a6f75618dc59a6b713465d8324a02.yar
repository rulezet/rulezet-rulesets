rule sig_20160324_ef5a6f75618dc59a6b713465d8324a02 {
  meta:
    description = "datamaliciousorder - file 20160324_ef5a6f75618dc59a6b713465d8324a02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c0742f0a44c3f5ae4df74953f2c511da5c9cd51e189acad5bd9e9c30518018"

  strings:
    $s1  = "return WScript.CreateObject(mGdHU);" fullword ascii
    $s2  = "var rU = true  , FUFZ = cKm[7] + cKm[9] + cKm[11];" fullword ascii
    $s3  = "return WYXPngH[0] + WYXPngH[2] + WYXPngH[4] + \".F\" + WYXPngH[7] + WYXPngH[9] + WYXPngH[12] + WYXPngH[14];" fullword ascii
    $s4  = "var WYXPngH = SEsWW(ypjaKscjrj+\" \"+\"System PP fWSDs Obj zSTRtC ect glxRlrb MZBiR\", \" \");" fullword ascii
    $s5  = "var cKm = (\"2.XMLHTTP JSYnAhq bkwav XML ream St HDBkiWmh AD kvgeIMn O wVwN D\").split(\" \");" fullword ascii
    $s6  = "kqfZ.open(crknS,RPRge,false);" fullword ascii
    $s7  = "function ahvg(HjwbO) {" fullword ascii
    $s8  = "return hvEddU/*F8rQ5o1MaA3dFZxkw1GrD0pEW*/.position=418-418;" fullword ascii
    $s9  = "return SvhF[gMQSHf[0]];" fullword ascii
    $s10 = "function yLdK(nvIQW) {" fullword ascii
    $s11 = "function MldY(ubgtN) {" fullword ascii
    $s12 = "return UUdtp.status;" fullword ascii
    $s13 = "function evQSkFaM(VkO) {" fullword ascii
    $s14 = "function wagJ(vYzIs,RPRge,crknS) {" fullword ascii
    $s15 = "if (HjwbO > 175113-516){return true;} else {return false;}" fullword ascii
    $s16 = "return VkO.size;" fullword ascii
    $s17 = "if(x>=d.length) {break;}" fullword ascii
    $s18 = "function YRxQ(mGdHU) {" fullword ascii
    $s19 = "function yuLnkSH(SvhF) {" fullword ascii
    $s20 = "function CTbi(RoLRB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}