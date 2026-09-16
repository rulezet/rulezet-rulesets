rule sig_20151217_b3054a6ebdd661c9b08e445183ef53d3 {
  meta:
    description = "datamaliciousorder - file 20151217_b3054a6ebdd661c9b08e445183ef53d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6736ef673c68172177f7018c9a583a72138510204c563345e8a4c25ad7fe9afa"

  strings:
    $s1  = "th.cos(75), 2) - 1)));} QfilOUBZC[tDILuLkBUex]++;}tDILuLkBUex++;} return LEvInDuXVQt}" fullword ascii
    $s2  = "function xiLKSEiYTQoAOhHQa(IzPEN){LEvInDuXVQt= '';tDILuLkBUex=Math.round((Math.pow(Math.sin(870), 2) + Math.pow(Math.cos(870), 2" ascii
    $s3  = ") - 1));while(true){if (tDILuLkBUex >= (576+6)/97){break;}QfilOUBZC[tDILuLkBUex]=Math.round((Math.pow(Math.sin(258), 2) + Math.p" ascii
    $s4  = "ow(Math.cos(258), 2) - 1)); while(true) { if(QfilOUBZC[tDILuLkBUex] > IzPEN[tDILuLkBUex].length-(353+293)/646) { break; } if (zR" ascii
    $s5  = "function xiLKSEiYTQoAOhHQa(IzPEN){LEvInDuXVQt= '';tDILuLkBUex=Math.round((Math.pow(Math.sin(870), 2) + Math.pow(Math.cos(870), 2" ascii
    $s6  = "function MJhHPDnRsWmFVNUJnmCuOnfgMFmbrJHfZsLSbENjQlXDYmqJxPKxOR(eOPAZlKEvZrbP,SpxoODfFtPLYbH){ return obnPYiN[ybvPsxCt[EADAT(eOP" ascii
    $s7  = "function MJhHPDnRsWmFVNUJnmCuOnfgMFmbrJHfZsLSbENjQlXDYmqJxPKxOR(eOPAZlKEvZrbP,SpxoODfFtPLYbH){ return obnPYiN[ybvPsxCt[EADAT(eOP" ascii
    $s8  = "function VHRAgdeDOKUgYdK(EvfCodLleBHvkOSkf,gXFOcXmURqmezwxrlldRWyLmUCMbKgtkHJ,zLRdlpfBJumsAoQvkTkgnXPevmuFRiUVRpK){eval(EvfCodLl" ascii
    $s9  = "function VHRAgdeDOKUgYdK(EvfCodLleBHvkOSkf,gXFOcXmURqmezwxrlldRWyLmUCMbKgtkHJ,zLRdlpfBJumsAoQvkTkgnXPevmuFRiUVRpK){eval(EvfCodLl" ascii
    $s10 = "function zRtzkWR(EEivBvGNhwpHiJBgbqGbBEUVsZtuiujskzBl) {return !qHhwqxVzXUt(nnmpWYaaoDjyzJr(EEivBvGNhwpHiJBgbqGbBEUVsZtuiujskzBl" ascii
    $s11 = "function qHhwqxVzXUt(DlErnRnrnVBRCB) {return isNaN(DlErnRnrnVBRCB);}" fullword ascii
    $s12 = "function nnmpWYaaoDjyzJr(VcWePvDuskFmtLZXlMv) {return parseFloat(VcWePvDuskFmtLZXlMv);}" fullword ascii
    $s13 = "Y);return VPHqq;}" fullword ascii
    $s14 = "function EADAT(DsATsDoVmCQ,AVlYWHotwvJRH,XnuaJFIY){rltT=VHfonaVflTdUkNjLI(DsATsDoVmCQ,AVlYWHotwvJRH);VPHqq=rltT.toString(XnuaJFI" ascii
    $s15 = "function T(XJSrISeLIYFaeM,BwGEKqagHtHwf,lcSeSmQLUzB) {XJSrISeLIYFaeM[BwGEKqagHtHwf]=lcSeSmQLUzB;}" fullword ascii
    $s16 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s17 = "function VHfonaVflTdUkNjLI(aFOHohaOhx,DMGlItcmqS) {return parseInt(aFOHohaOhx,DMGlItcmqS);}" fullword ascii
    $s18 = "function EADAT(DsATsDoVmCQ,AVlYWHotwvJRH,XnuaJFIY){rltT=VHfonaVflTdUkNjLI(DsATsDoVmCQ,AVlYWHotwvJRH);VPHqq=rltT.toString(XnuaJFI" ascii
    $s19 = "function Z(nCvChubdONTV,LLCiICMQHakiQp){nCvChubdONTV.push(LLCiICMQHakiQp);}" fullword ascii
    $s20 = "function zRtzkWR(EEivBvGNhwpHiJBgbqGbBEUVsZtuiujskzBl) {return !qHhwqxVzXUt(nnmpWYaaoDjyzJr(EEivBvGNhwpHiJBgbqGbBEUVsZtuiujskzBl" ascii

  condition:
    uint16(0) == 0x6279 and
    8 of them
}