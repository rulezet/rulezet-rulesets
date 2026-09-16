rule sig_20160314_6921d9b58e5ad95c23ec6413494030d6 {
  meta:
    description = "datamaliciousorder - file 20160314_6921d9b58e5ad95c23ec6413494030d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c6a5174cd09af0fbebc032724b42501b6b4a618e0194bcd118c1cb78d4e548e"

  strings:
    $s1  = "return uqeWgtM[0] + uqeWgtM[2] + uqeWgtM[4] + \".F\" + uqeWgtM[7] + uqeWgtM[9] + uqeWgtM[12] + uqeWgtM[14];" fullword ascii
    $s2  = "var jK = true  , rBqk = OxA[7] + OxA[9] + OxA[11];" fullword ascii
    $s3  = "var uqeWgtM = \"Sc DVbXBAA r XmdcMrARy ipting LcGaUFp xST ile eDuIoOMnLXVtLy System Zq ZWTdX Obj Vrhklg ect traeSai Jmzyi\".spli" ascii
    $s4  = "var uqeWgtM = \"Sc DVbXBAA r XmdcMrARy ipting LcGaUFp xST ile eDuIoOMnLXVtLy System Zq ZWTdX Obj Vrhklg ect traeSai Jmzyi\".spli" ascii
    $s5  = "rMyaH.open(XzoYh,eceEC,false);" fullword ascii
    $s6  = "var OxA = (\"2.XMLHTTP QDqxlQO QWzSY XML ream St zBxsvnDV AD XioSvnL O mWBR D\").split(\" \");" fullword ascii
    $s7  = "function SlOb(mpfYr) {" fullword ascii
    $s8  = "function eGZw(rMyaH,eceEC,XzoYh) {" fullword ascii
    $s9  = "function tDHJCbY(vldj) {" fullword ascii
    $s10 = "return PbOT.ExpandEnvironmentStrings(ntNiB);" fullword ascii
    $s11 = "return kaT.size;" fullword ascii
    $s12 = "return YkJrW;" fullword ascii
    $s13 = "return ffndfph(cX,FwIPM[315-309]+FwIPM[900-893]+FwIPM[382-374]);" fullword ascii
    $s14 = "function qgcO(fXZeM) {" fullword ascii
    $s15 = "fpn = H; break; " fullword ascii
    $s16 = "return UNSdBFh" fullword ascii
    $s17 = "if (fXZeM == 347-147){return true;} else {return false;}" fullword ascii
    $s18 = "function KIIVpUDu() {" fullword ascii
    $s19 = "function IlOH(ycHRS,OZhKj) {" fullword ascii
    $s20 = "function SsaNsQaro() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}