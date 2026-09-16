rule sig_20151215_0b72a3bfbb844f57ae217f9cec8fae2f {
  meta:
    description = "datamaliciousorder - file 20151215_0b72a3bfbb844f57ae217f9cec8fae2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9197012184f0007beff224f8f1a39f5984e0cbe1111d38b73cc6203be3241bb0"

  strings:
    $s1  = "ath.pow(Math.cos(898), 2) - 1)); while(true) { if(MpXfnhFye[efudozdvTMG] > vmmFj[efudozdvTMG].length-(607+325)/932) { break; } i" ascii
    $s2  = ".pow(Math.cos(663), 2) - 1)));} MpXfnhFye[efudozdvTMG]++;}} return MynRUcLJVfI}" fullword ascii
    $s3  = "function ZLiXtAvwBbCXnMkgQ(vmmFj){MynRUcLJVfI= P[1831];for(efudozdvTMG=Math.round((Math.pow(Math.sin(159), 2) + Math.pow(Math.co" ascii
    $s4  = "function ZLiXtAvwBbCXnMkgQ(vmmFj){MynRUcLJVfI= P[1831];for(efudozdvTMG=Math.round((Math.pow(Math.sin(159), 2) + Math.pow(Math.co" ascii
    $s5  = "qPEIrtGZJVZdmmcuCfIOBsbkpUkuBawigFlr([vmmFj[efudozdvTMG][MpXfnhFye[efudozdvTMG]]], Math.round((Math.pow(Math.sin(663), 2) + Math" ascii
    $s6  = "function D(MNXUpMwJpLSg,RCveDITzwGLWxW){MNXUpMwJpLSg.push(RCveDITzwGLWxW);}function F6(vOXEXbEpLoTCPOxa){if(WRejLKH(vOXEXbEpLoTC" ascii
    $s7  = "POxa)) {return (String.fromCharCode(vOXEXbEpLoTCPOxa) + String.fromCharCode((25859+301)/545));}}" fullword ascii
    $s8  = "function WRejLKH(WzFYDqaezbodLshGNLlbtzCrjPgPWshPahrB) {return !isNaN(parseFloat(WzFYDqaezbodLshGNLlbtzCrjPgPWshPahrB)) && isFin" ascii
    $s9  = "function WRejLKH(WzFYDqaezbodLshGNLlbtzCrjPgPWshPahrB) {return !isNaN(parseFloat(WzFYDqaezbodLshGNLlbtzCrjPgPWshPahrB)) && isFin" ascii
    $s10 = "var P=new Array();" fullword ascii
    $s11 = "function AJaaanKTTLV(NeMpGjLG,lxAEok){return NeMpGjLG.split(lxAEok)}" fullword ascii
    $s12 = "function gUWXo(bIWnHejuRbm,DtHhTYlQgVOmU,HqJGoQBM){ERZy=parseInt(bIWnHejuRbm,DtHhTYlQgVOmU);bYdiP=ERZy.toString(HqJGoQBM);return" ascii
    $s13 = "function lTutvkiBmJGtVjpBneqPEIrtGZJVZdmmcuCfIOBsbkpUkuBawigFlr(fjmKWRZjbTnLt,EKvozgCHpPycXP){ return OmPRLYL[BqKkISDy[gUWXo(fjm" ascii
    $s14 = " bYdiP;}function AsqAfjKCVCcuXVc(DMwdnHUSLbUEyAtME,vhWhRxTmJiWlukDAalOKNjgJxRWGAmPvzC,QahfIJmoFCfMMSrKPxaEeGwCyDneyhThyta){eval(" ascii
    $s15 = "function gUWXo(bIWnHejuRbm,DtHhTYlQgVOmU,HqJGoQBM){ERZy=parseInt(bIWnHejuRbm,DtHhTYlQgVOmU);bYdiP=ERZy.toString(HqJGoQBM);return" ascii
    $s16 = "function D(MNXUpMwJpLSg,RCveDITzwGLWxW){MNXUpMwJpLSg.push(RCveDITzwGLWxW);}function F6(vOXEXbEpLoTCPOxa){if(WRejLKH(vOXEXbEpLoTC" ascii
    $s17 = "function lTutvkiBmJGtVjpBneqPEIrtGZJVZdmmcuCfIOBsbkpUkuBawigFlr(fjmKWRZjbTnLt,EKvozgCHpPycXP){ return OmPRLYL[BqKkISDy[gUWXo(fjm" ascii
    $s18 = "function AsqAfjKCVCcuXVc(DMwdnHUSLbUEyAtME){eval(DMwdnHUSLbUEyAtME)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}