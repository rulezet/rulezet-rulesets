rule sig_20160405_cef72bb1556c60ec290299d81296d362 {
  meta:
    description = "datamaliciousorder - file 20160405_cef72bb1556c60ec290299d81296d362.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1523c37db362a6de7a9275ed26e64606c17f6a44c1a342418556bc2a9dd4da40"

  strings:
    $s1  = "function vfiRcp(EUMr,Efgtji) {" fullword ascii
    $s2  = "vfiRcp(aSn,yoUl);" fullword ascii
    $s3  = "return fcJOaRh[0] + fcJOaRh[2] + fcJOaRh[4] + \".F\" + fcJOaRh[7] + fcJOaRh[9] + fcJOaRh[12] + fcJOaRh[14];" fullword ascii
    $s4  = "var iA = true  , CQzZ = bHW[7] + bHW[9] + bHW[11];" fullword ascii
    $s5  = "ueWw.open(wdGQv,lgHwG,false);" fullword ascii
    $s6  = "if (cBFAR == 941-741){return true;} else {return false;}" fullword ascii
    $s7  = "return oKeU[otWypJ[0]];" fullword ascii
    $s8  = "function OGeuF(nbt,iECuL) {" fullword ascii
    $s9  = "function tbXztH(wEjOGjZ) {" fullword ascii
    $s10 = "function uYfnSvZjV(WuLCp) {" fullword ascii
    $s11 = "if (kiwFz > 191103-235){return true;} else {return false;}" fullword ascii
    $s12 = "return aXsjM;" fullword ascii
    $s13 = "function XvcM(sEJJs,jfLLB) {" fullword ascii
    $s14 = "function vhyHh(BrBVnm) {" fullword ascii
    $s15 = "var yoUl = SlK+tRguhG[0]+tRguhG[1];" fullword ascii
    $s16 = "return DGDFvpp;" fullword ascii
    $s17 = "function xNtv(rMAtI) {" fullword ascii
    $s18 = "return vdO.size;" fullword ascii
    $s19 = "function YzVKNTr(WpeD,zAgbj) {" fullword ascii
    $s20 = "function RPWpQYks(vdO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}