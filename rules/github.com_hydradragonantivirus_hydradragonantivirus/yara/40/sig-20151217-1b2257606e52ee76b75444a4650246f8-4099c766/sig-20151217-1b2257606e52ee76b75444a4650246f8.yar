rule sig_20151217_1b2257606e52ee76b75444a4650246f8 {
  meta:
    description = "datamaliciousorder - file 20151217_1b2257606e52ee76b75444a4650246f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be0eff8dad68fc6a8db89f1564bc6062b9c67a87965b6aa66a95b18342a25bfc"

  strings:
    $s1  = ") - 1));while(true){if (jqXoppMjfBQ >= (3516+966)/747){break;}oRQurVUpf[jqXoppMjfBQ]=Math.round((Math.pow(Math.sin(807), 2) + Ma" ascii
    $s2  = "function WbeMJfUiwMxLVZSlS(qZoPW){KDSHwPwaOxm= '';jqXoppMjfBQ=Math.round((Math.pow(Math.sin(115), 2) + Math.pow(Math.cos(115), 2" ascii
    $s3  = "(Math.cos(86), 2) - 1)));} oRQurVUpf[jqXoppMjfBQ]++;}jqXoppMjfBQ++;} return KDSHwPwaOxm}" fullword ascii
    $s4  = "th.pow(Math.cos(807), 2) - 1)); while(true) { if(oRQurVUpf[jqXoppMjfBQ] > qZoPW[jqXoppMjfBQ].length-(421+486)/907) { break; } if" ascii
    $s5  = "function WbeMJfUiwMxLVZSlS(qZoPW){KDSHwPwaOxm= '';jqXoppMjfBQ=Math.round((Math.pow(Math.sin(115), 2) + Math.pow(Math.cos(115), 2" ascii
    $s6  = "function YCTCJajbewtlyWstXoTffVsSmCvcSHGpNTMOKqPDeaIraoXQJjagER(fCBxYpKGYtHWn,DtQfJsBINbyDEe){ return RPPzSnQ[aotOULCX[AKJhu(fCB" ascii
    $s7  = "function TdBuymp(lsvtAUPrJcRPltpREabhSyQQGWqgjdetkaHs) {return !EgfAOBgoDzO(ygvYdDAZyDItlvG(lsvtAUPrJcRPltpREabhSyQQGWqgjdetkaHs" ascii
    $s8  = "function YCTCJajbewtlyWstXoTffVsSmCvcSHGpNTMOKqPDeaIraoXQJjagER(fCBxYpKGYtHWn,DtQfJsBINbyDEe){ return RPPzSnQ[aotOULCX[AKJhu(fCB" ascii
    $s9  = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii
    $s10 = "function nWqSQXsmrgwM(FqcwDFOFdPHLH) {return isFinite(FqcwDFOFdPHLH);}" fullword ascii
    $s11 = "function TdBuymp(lsvtAUPrJcRPltpREabhSyQQGWqgjdetkaHs) {return !EgfAOBgoDzO(ygvYdDAZyDItlvG(lsvtAUPrJcRPltpREabhSyQQGWqgjdetkaHs" ascii
    $s12 = "function EgfAOBgoDzO(naLpfpCKWYbSfS) {return isNaN(naLpfpCKWYbSfS);}" fullword ascii
    $s13 = "l);return Zvwsh;}" fullword ascii
    $s14 = "function P(kLBkyDoVWaKX,cnCUdhzRDVuIIb){kLBkyDoVWaKX.push(cnCUdhzRDVuIIb);}" fullword ascii
    $s15 = "function AKJhu(HQvGRxhFKcs,sJyCVsEakNOBY,SfqnEeTl){SsNz=wfPnhGpTlTOksuAoR(HQvGRxhFKcs,sJyCVsEakNOBY);Zvwsh=SsNz.toString(SfqnEeT" ascii
    $s16 = "function I(eGygnLQQpjIHFC,FJNEBMLnkDgaR,HDNqEXaJOXL) {eGygnLQQpjIHFC[FJNEBMLnkDgaR]=HDNqEXaJOXL;}" fullword ascii
    $s17 = "function wfPnhGpTlTOksuAoR(MoLHxoWrSK,pyWvJSCvvF) {return parseInt(MoLHxoWrSK,pyWvJSCvvF);}" fullword ascii
    $s18 = "function ygvYdDAZyDItlvG(KBEohTZsBHQjtinDVqP) {return parseFloat(KBEohTZsBHQjtinDVqP);}" fullword ascii
    $s19 = "function AKJhu(HQvGRxhFKcs,sJyCVsEakNOBY,SfqnEeTl){SsNz=wfPnhGpTlTOksuAoR(HQvGRxhFKcs,sJyCVsEakNOBY);Zvwsh=SsNz.toString(SfqnEeT" ascii
    $s20 = "var k = new Array();k[0]=[];k[0][0]='d';k[0][1]='a';k[0][2]='d';k[0][3]='a';k[0][4]='46';k[0][5]='3d';k[0][6]='42';k[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6f61 and
    8 of them
}