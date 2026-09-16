rule sig_20151216_bac777b945d18b78b32e523997bf9761 {
  meta:
    description = "datamaliciousorder - file 20151216_bac777b945d18b78b32e523997bf9761.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3c081b0132f28b51fd009853310837eb3b04ba32b0f7ddfcb0112ddb8e892b"

  strings:
    $s1  = "function PzLwJxrGwraqgjSzh(ZhrKz){pTykimZqzqB= '';DNmWeAuzhtT=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s2  = ".pow(Math.cos(569), 2) - 1)); while(true) { if(NtezpYgaa[DNmWeAuzhtT] > ZhrKz[DNmWeAuzhtT].length-(-735+870)/135) { break; } if " ascii
    $s3  = "w(Math.cos(174), 2) - 1)));} NtezpYgaa[DNmWeAuzhtT]++;}DNmWeAuzhtT++;} return pTykimZqzqB}" fullword ascii
    $s4  = ") - 1));while(true){if (DNmWeAuzhtT >= (1657+5)/277){break;}NtezpYgaa[DNmWeAuzhtT]=Math.round((Math.pow(Math.sin(569), 2) + Math" ascii
    $s5  = "function PzLwJxrGwraqgjSzh(ZhrKz){pTykimZqzqB= '';DNmWeAuzhtT=Math.round((Math.pow(Math.sin(739), 2) + Math.pow(Math.cos(739), 2" ascii
    $s6  = "function MlFMXkb(SpbWVPfeqQEHbQqSuxHKhlErPuHAgieyFCjn) {return !lgRxpJdDLvw(PzrSUVIHDDSdchK(SpbWVPfeqQEHbQqSuxHKhlErPuHAgieyFCjn" ascii
    $s7  = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s8  = "function MlFMXkb(SpbWVPfeqQEHbQqSuxHKhlErPuHAgieyFCjn) {return !lgRxpJdDLvw(PzrSUVIHDDSdchK(SpbWVPfeqQEHbQqSuxHKhlErPuHAgieyFCjn" ascii
    $s9  = "function SEskhxSpnnyYPFj(mNJMUqgEAtFbJDHML,gzcIbIPcddqMEjydxlQzVczikkhqVcJAqL,lwLTqlIOiBUOlzRQFjguvCGgEiyQJPUdtXr){eval(mNJMUqgE" ascii
    $s10 = "var I = new Array();I[0]=[];I[0][0]='d';I[0][1]='a';I[0][2]='d';I[0][3]='a';I[0][4]='46';I[0][5]='3d';I[0][6]='42';I[0][7]='14';" ascii
    $s11 = "function aXaqx(ubbjEtFlPiN,xRKMlvzIkEEpp,gxKgcMtd){icDC=aPIvwEZxMktXvVRhk(ubbjEtFlPiN,xRKMlvzIkEEpp);ggdli=icDC.toString(gxKgcMt" ascii
    $s12 = "function T(TmSdaFTiZOnU,pokYCqpNoCfyAF){TmSdaFTiZOnU.push(pokYCqpNoCfyAF);}" fullword ascii
    $s13 = "function lgRxpJdDLvw(zHfSbtLaVZSWso) {return isNaN(zHfSbtLaVZSWso);}" fullword ascii
    $s14 = "function PzrSUVIHDDSdchK(pdobWVkHUgqpRKXTZaD) {return parseFloat(pdobWVkHUgqpRKXTZaD);}" fullword ascii
    $s15 = "function S(aOZbOXuayIPPyS,YRCrUhnzaPfyU,aoIMCWRMrzt) {aOZbOXuayIPPyS[YRCrUhnzaPfyU]=aoIMCWRMrzt;}" fullword ascii
    $s16 = "function aXaqx(ubbjEtFlPiN,xRKMlvzIkEEpp,gxKgcMtd){icDC=aPIvwEZxMktXvVRhk(ubbjEtFlPiN,xRKMlvzIkEEpp);ggdli=icDC.toString(gxKgcMt" ascii
    $s17 = "function NxRzNADPtUrwsfzkYMiQAJensAlsnAeDFBQxrGEgMfRaBRQiMgKBRy(cFLmDaNdfkcGI,GCddAjDdxojMOt){ return JGZMtWS[peOloIao[aXaqx(cFL" ascii
    $s18 = "function NxRzNADPtUrwsfzkYMiQAJensAlsnAeDFBQxrGEgMfRaBRQiMgKBRy(cFLmDaNdfkcGI,GCddAjDdxojMOt){ return JGZMtWS[peOloIao[aXaqx(cFL" ascii
    $s19 = "function qEBQpdeLXrBK(aPwmIlsbdyrSz) {return isFinite(aPwmIlsbdyrSz);}" fullword ascii
    $s20 = "function aPIvwEZxMktXvVRhk(eBAeQaPlPA,XnnHBCFIjf) {return parseInt(eBAeQaPlPA,XnnHBCFIjf);}" fullword ascii

  condition:
    uint16(0) == 0x6570 and
    8 of them
}