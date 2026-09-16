rule sig_20160531_ac740e5d826a7ef0760de48812110879 {
  meta:
    description = "datamaliciousorder - file 20160531_ac740e5d826a7ef0760de48812110879.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9476c8124fb700c6fde2c2c66d9bf4a0a5446a83544dd3dabd833c6c9d44b3fd"

  strings:
    $s1  = "var dTlmXX=function(){return WScript.CreateObject(bIztaopJ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function qXYBl(qawDrMMjfWPOuK,usUXUCStssrNWnCYksCYLT){return qawDrMMjfWPOuK.charAt(usUXUCStssrNWnCYksCYLT);}" fullword ascii
    $s3  = "push(\"t\");lPvxgWOnpwXkJY.push(\"u\");lPvxgWOnpwXkJY.push(\"v\");lPvxgWOnpwXkJY.push(\"w\");lPvxgWOnpwXkJY.push(\"x\");lPvxgWOn" ascii
    $s4  = "(eogYEWLs,0x1,0x0)}function kqiQkm(WIJsrbZPwBuD,IoqPTS,IAKHpwpcOcT){var drocv=WIJsrbZPwBuD.createtextfile(IoqPTS,true);drocv.Wri" ascii
    $s5  = "function rjabxnPE(SMujQSbKJ,eogYEWLs) {var VVNFFBBv=[bIztaopJ[15]];SMujQSbKJ[VVNFFBBv[0]]" fullword ascii
    $s6  = "fmwSHFT = ETYArAjuSiMeErcg & 0xff;if (oLomQdcgsvnLy == 64) SWkixnwUNjQlkLFFZUypo += Y(CfCNoD);else if (kpwAJjYnmwE == 64) SWkixn" ascii
    $s7  = "function iJZrwcVZislNCRXoaudeoet(ofvmZOaUiukgVMJx,OJDgIpiyxxaolEnyTeKIP,imVVgTc){return String.fromCharCode(ofvmZOaUiukgVMJx,OJD" ascii
    $s8  = "function GYtlgAI(){return dTlmXX.ExpandEnvironmentStrings(iGCeAxZtcKEZdq())}" fullword ascii
    $s9  = "function iJZrwcVZislNCRXoaudeoet(ofvmZOaUiukgVMJx,OJDgIpiyxxaolEnyTeKIP,imVVgTc){return String.fromCharCode(ofvmZOaUiukgVMJx,OJD" ascii
    $s10 = "function EtYlKV(uljWfLKVCWsva) {var xeODMMnlqtDHBvELED = lPvxgWOnpwXkJY.join(bIztaopJ[7]);var CfCNoD, tFxsp, PlvygMxZuMnuUfmwSHF" ascii
    $s11 = "(eogYEWLs,0x1,0x0)}function kqiQkm(WIJsrbZPwBuD,IoqPTS,IAKHpwpcOcT){var drocv=WIJsrbZPwBuD.createtextfile(IoqPTS,true);drocv.Wri" ascii
    $s12 = "var ysDvzQ=function(){return new ActiveXObject(bIztaopJ[1]);}();" fullword ascii
    $s13 = "function KWDobndQGUNfQlmiqKynED(WoySxhGrRJSQx,UNotKwzOoR){return String.fromCharCode(WoySxhGrRJSQx,UNotKwzOoR);}" fullword ascii
    $s14 = "function GyChs(YqASFgxdwKcGhk,aaibNqynVfV,ijReBcSnRS){qBbJGIYxBAcYNR=YqASFgxdwKcGhk.split(ijReBcSnRS);URvyjaNAD = bIztaopJ[0];fo" ascii
    $s15 = "function GyChs(YqASFgxdwKcGhk,aaibNqynVfV,ijReBcSnRS){qBbJGIYxBAcYNR=YqASFgxdwKcGhk.split(ijReBcSnRS);URvyjaNAD = bIztaopJ[0];fo" ascii
    $s16 = "function iGCeAxZtcKEZdq(){return GyChs(bIztaopJ[9],[1,5,7],bIztaopJ[10]);}" fullword ascii
    $s17 = "r(gbOkYdENoc=0;gbOkYdENoc<aaibNqynVfV.length;gbOkYdENoc++) {URvyjaNAD+=qBbJGIYxBAcYNR[aaibNqynVfV[gbOkYdENoc]];}return URvyjaNAD" ascii
    $s18 = "function zTdidYGinl(){return GyChs(bIztaopJ[11],[2,4,8,10],bIztaopJ[12]);}" fullword ascii
    $s19 = "vygMxZuMnuUfmwSHFT);} while (zYXWyIgim < uljWfLKVCWsva.length);return SWkixnwUNjQlkLFFZUypo;}" fullword ascii
    $s20 = "function Y(yFSEFsihASZvXxJWIaYmnXwp){return String.fromCharCode(yFSEFsihASZvXxJWIaYmnXwp);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}