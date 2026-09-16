rule sig_20160321_79c5dfbfbd93732f5c44411e645309ae {
  meta:
    description = "datamaliciousorder - file 20160321_79c5dfbfbd93732f5c44411e645309ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee80e66d00070141afdbf4f467f75e7e2f8301b29f9ee3095a47a8dee3cffa1"

  strings:
    $s1  = "return WScript.CreateObject(GkVxy);" fullword ascii
    $s2  = "return FQclPea[0] + FQclPea[2] + FQclPea[4] + \".F\" + FQclPea[7] + FQclPea[9] + FQclPea[12] + FQclPea[14];" fullword ascii
    $s3  = "var Sr = true  , AkMV = SGJ[7] + SGJ[9] + SGJ[11];" fullword ascii
    $s4  = "var FQclPea = UakMm(OFjhXUewxo+\" \"+\"System Ku rthdT Obj DVOEeI ect CUOkNiF XwvIG\", \" \");" fullword ascii
    $s5  = "var SGJ = (\"2.XMLHTTP gZaHGwf vergo XML ream St gInYwGML AD TpyJaAq O cqXa D\").split(\" \");" fullword ascii
    $s6  = "kxFOR.open(YwSii,JtyNt,false);" fullword ascii
    $s7  = "return KaKGyA.position=231-231;" fullword ascii
    $s8  = "function QjpOLOFp(zvNm) {" fullword ascii
    $s9  = "function SDWAIeh(EmuR) {" fullword ascii
    $s10 = "return ERS.size;" fullword ascii
    $s11 = "return lHE.split(OCpgg);" fullword ascii
    $s12 = "function XLUBHaYfC(lkOphDmvWcH) {" fullword ascii
    $s13 = "function YxNkocOKe(CVvbA) {" fullword ascii
    $s14 = "if(m>=D.length) {break;}" fullword ascii
    $s15 = "return new ActiveXObject(IcKKlr);" fullword ascii
    $s16 = "NoI = m; break; " fullword ascii
    $s17 = "function TUAq(BQeAh,naCec) {" fullword ascii
    $s18 = "if (U >= vReBQ.length) {break;}" fullword ascii
    $s19 = "function qQXH(eiuXh) {" fullword ascii
    $s20 = "function nork(GkVxy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}