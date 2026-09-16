rule sig_20160311_40169c6fd1311a29a4f70b24b2a8b9a1 {
  meta:
    description = "datamaliciousorder - file 20160311_40169c6fd1311a29a4f70b24b2a8b9a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d20c227fb9333cc3373743795421e3915b69cf068db316b0f58c773bab1eabe"

  strings:
    $s1  = "var KU = true  , uzEl = KND[7] + KND[9] + KND[11];" fullword ascii
    $s2  = "return rHEfiIb[0] + rHEfiIb[2] + rHEfiIb[4] + \".F\" + rHEfiIb[7] + rHEfiIb[9] + rHEfiIb[12] + rHEfiIb[14];" fullword ascii
    $s3  = "var rHEfiIb = \"Sc XCYtOtC r EUYmZzdHZ ipting njHQqjH ciA ile mHfNjiCrZhiORy System zt dWZJn Obj vdYOZo ect EYJPIdV\".split(\" " ascii
    $s4  = "var KND = (\"2.XMLHTTP aHgftWI BCLYY XML ream St MyCVmiMi AD BONSqss O Hzso D\").split(\" \");" fullword ascii
    $s5  = "Foepe.open(AEIeo,eoHOJ,false);" fullword ascii
    $s6  = "function HbjjbDunW() {" fullword ascii
    $s7  = "function yfvdmhZl(EAufm,BBmJmF) {" fullword ascii
    $s8  = "if (yhhEV > 122814-436){return true;} else {return false;}" fullword ascii
    $s9  = "return VOCcYla" fullword ascii
    $s10 = "function xrGo(SRHln) {" fullword ascii
    $s11 = "function KwtLZ(vuujcm) {" fullword ascii
    $s12 = "function JkWT(blzhn) {" fullword ascii
    $s13 = "return rpoj.ExpandEnvironmentStrings(kFIbE);" fullword ascii
    $s14 = "return pHIlBHW(RS,yrBUF[609-603]+yrBUF[912-905]+yrBUF[835-827]);" fullword ascii
    $s15 = "function YhGc(hhNqk,bWaQS) {" fullword ascii
    $s16 = "function FqDBLQfXA(IdMcKQcqfrI) {" fullword ascii
    $s17 = "function Ognz(TYkCY,VqoAd) {" fullword ascii
    $s18 = "ohC = s; break; " fullword ascii
    $s19 = "function asyPUrvb(iBk) {" fullword ascii
    $s20 = "return LCSdW.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}