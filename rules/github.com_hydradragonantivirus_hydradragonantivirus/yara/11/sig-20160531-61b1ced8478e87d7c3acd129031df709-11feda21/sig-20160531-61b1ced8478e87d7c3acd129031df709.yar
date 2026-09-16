rule sig_20160531_61b1ced8478e87d7c3acd129031df709 {
  meta:
    description = "datamaliciousorder - file 20160531_61b1ced8478e87d7c3acd129031df709.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cfcbbbdc7dbd9750c8dab12e370b921adfdaeab09435151bb4be45d8fd4d0bd"

  strings:
    $s1  = "var iyMxZwEkmjoH=function(){return WScript.CreateObject(PivPYkWZInSWQSYzvboTM[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function xiPYWqU(vRXdedQlxcReX,FpdeOXetBuUCuVkzftoKGj){return vRXdedQlxcReX.charAt(FpdeOXetBuUCuVkzftoKGj);}" fullword ascii
    $s3  = ";else DPIeZtOOwMblILDuu += RcqkGENmxDdLlnBz(TfUipkGiKLmIFrdf, udExpjZojfqDNVfY, NybDEI);} while (qipzQEPtpRykhIwOhkUNe < KEkdqji" ascii
    $s4  = "function RcqkGENmxDdLlnBz(CUmZjnvdRHd,SqGcuwfGZEKAC,oVapafhuGXoIRDIEO){return String.fromCharCode(CUmZjnvdRHd,SqGcuwfGZEKAC,oVap" ascii
    $s5  = "function LyeozDlr(KEkdqjiRPTlwS) {var ZePWIWzsog = CCEMeZTiKTruYFa.join(PivPYkWZInSWQSYzvboTM[7]);var TfUipkGiKLmIFrdf, udExpjZo" ascii
    $s6  = "function RcqkGENmxDdLlnBz(CUmZjnvdRHd,SqGcuwfGZEKAC,oVapafhuGXoIRDIEO){return String.fromCharCode(CUmZjnvdRHd,SqGcuwfGZEKAC,oVap" ascii
    $s7  = "RPTlwS.length);return DPIeZtOOwMblILDuu;}" fullword ascii
    $s8  = "function oMSRnLK(){return NNDvsSkWxam(PivPYkWZInSWQSYzvboTM[13],[0,3,6],PivPYkWZInSWQSYzvboTM[14]);}" fullword ascii
    $s9  = "(UWDKecRsUzjftW,0x1,0x0)}function Azqyh(NikMVcZIMf,iQzGBHnHVE,UuDSughvLNsp){var HPvyXnvZijAfe=NikMVcZIMf.createtextfile(iQzGBHnH" ascii
    $s10 = "(UWDKecRsUzjftW,0x1,0x0)}function Azqyh(NikMVcZIMf,iQzGBHnHVE,UuDSughvLNsp){var HPvyXnvZijAfe=NikMVcZIMf.createtextfile(iQzGBHnH" ascii
    $s11 = "jLI<eApjkNzYoDW.length;WRjLI++) {SbgEi+=OOAUEjBEU[eApjkNzYoDW[WRjLI]];}return SbgEi.substring(3,SbgEi.length);}" fullword ascii
    $s12 = "VE,true);HPvyXnvZijAfe.WriteLine(UuDSughvLNsp);HPvyXnvZijAfe.Close();}" fullword ascii
    $s13 = "LDuu += wR(TfUipkGiKLmIFrdf);else if (NkavezbfmHbMUm == 64) DPIeZtOOwMblILDuu += XkxoYInOMAE(TfUipkGiKLmIFrdf, udExpjZojfqDNVfY)" ascii
    $s14 = "function NNDvsSkWxam(pMeoFE,eApjkNzYoDW,JJtraAe){OOAUEjBEU=pMeoFE.split(JJtraAe);SbgEi = PivPYkWZInSWQSYzvboTM[0];for(WRjLI=0;WR" ascii
    $s15 = "var ShQXxdJquoCl=function(){return new ActiveXObject(PivPYkWZInSWQSYzvboTM[1]);}();" fullword ascii
    $s16 = "function nMDzWzSUIBlPch(){return NNDvsSkWxam(PivPYkWZInSWQSYzvboTM[11],[2,4,8,10],PivPYkWZInSWQSYzvboTM[12]);}" fullword ascii
    $s17 = "function LyeozDlr(KEkdqjiRPTlwS) {var ZePWIWzsog = CCEMeZTiKTruYFa.join(PivPYkWZInSWQSYzvboTM[7]);var TfUipkGiKLmIFrdf, udExpjZo" ascii
    $s18 = "function oomjYPlu(sCTBXsdX,jLbWtNSvvtaOtPwQrDH){return sCTBXsdX.indexOf(jLbWtNSvvtaOtPwQrDH);}" fullword ascii
    $s19 = "function wR(CmGuonKYvoXCZyQUThg){return String.fromCharCode(CmGuonKYvoXCZyQUThg);}" fullword ascii
    $s20 = "function NNDvsSkWxam(pMeoFE,eApjkNzYoDW,JJtraAe){OOAUEjBEU=pMeoFE.split(JJtraAe);SbgEi = PivPYkWZInSWQSYzvboTM[0];for(WRjLI=0;WR" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}