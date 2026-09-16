rule sig_20151217_ed4b03f76122854e8191429115052f1f {
  meta:
    description = "datamaliciousorder - file 20151217_ed4b03f76122854e8191429115052f1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "117f51da7cabe4bec32bfb5e5fb83f6fbc4c07dbb507fae23948df61610fd0f1"

  strings:
    $s1  = "Math.cos(702), 2) - 1)));} CvxqFxOEg[ygsiCyLAmRy]++;}ygsiCyLAmRy++;} return JgftWNkTgcH}" fullword ascii
    $s2  = "th.pow(Math.cos(495), 2) - 1)); while(true) { if(CvxqFxOEg[ygsiCyLAmRy] > QkynY[ygsiCyLAmRy].length-(213+187)/400) { break; } if" ascii
    $s3  = "function EKgIsghWULdQSfeRl(QkynY){JgftWNkTgcH= '';ygsiCyLAmRy=Math.round((Math.pow(Math.sin(363), 2) + Math.pow(Math.cos(363), 2" ascii
    $s4  = ") - 1));while(true){if (ygsiCyLAmRy >= (3644+922)/761){break;}CvxqFxOEg[ygsiCyLAmRy]=Math.round((Math.pow(Math.sin(495), 2) + Ma" ascii
    $s5  = "function EKgIsghWULdQSfeRl(QkynY){JgftWNkTgcH= '';ygsiCyLAmRy=Math.round((Math.pow(Math.sin(363), 2) + Math.pow(Math.cos(363), 2" ascii
    $s6  = "function UjhvpXc(VALjsDUZgEcTOIgAJYFoVQuXRraQEDydjILW) {return !ukPIwHHiwKJ(pxZoOgYGWuJjyst(VALjsDUZgEcTOIgAJYFoVQuXRraQEDydjILW" ascii
    $s7  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s8  = "function UjhvpXc(VALjsDUZgEcTOIgAJYFoVQuXRraQEDydjILW) {return !ukPIwHHiwKJ(pxZoOgYGWuJjyst(VALjsDUZgEcTOIgAJYFoVQuXRraQEDydjILW" ascii
    $s9  = "function HAazOzMaNKTr(QPQkKlAtabKuU) {return isFinite(QPQkKlAtabKuU);}" fullword ascii
    $s10 = "function THjMBkNVePhMxKkCU(agKDQpogqU,ZyzayPQuCl) {return parseInt(agKDQpogqU,ZyzayPQuCl);}" fullword ascii
    $s11 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s12 = "function ytQLQoewsCmpNuVPtqUcyBkQMntTVnANgOWBHuydgSKHPRIVSCChAd(zujRXiXFEBXJb,sPLexEBAxmwOuw){ return kwHGjCS[PJeIPSsN[NkqIs(zuj" ascii
    $s13 = "function NkqIs(YxygRBnTjvD,ZpJfknpIRTTvL,ySDkLlRh){gxlL=THjMBkNVePhMxKkCU(YxygRBnTjvD,ZpJfknpIRTTvL);SSFPl=gxlL.toString(ySDkLlR" ascii
    $s14 = "function cUgXTsRlcWmYHWY(IsxifnJDDOxcWdyxr,krjOtqpBddQBFLWsoKGgZAPhiGmetbesef,MXtWrHACLLrvACDscyHKpOXbFsvnchSraaH){eval(IsxifnJD" ascii
    $s15 = "function ukPIwHHiwKJ(hxcLRCFkccXCRs) {return isNaN(hxcLRCFkccXCRs);}" fullword ascii
    $s16 = "h);return SSFPl;}" fullword ascii
    $s17 = "function cUgXTsRlcWmYHWY(IsxifnJDDOxcWdyxr,krjOtqpBddQBFLWsoKGgZAPhiGmetbesef,MXtWrHACLLrvACDscyHKpOXbFsvnchSraaH){eval(IsxifnJD" ascii
    $s18 = "function NkqIs(YxygRBnTjvD,ZpJfknpIRTTvL,ySDkLlRh){gxlL=THjMBkNVePhMxKkCU(YxygRBnTjvD,ZpJfknpIRTTvL);SSFPl=gxlL.toString(ySDkLlR" ascii
    $s19 = "function S(jLXMEBNtNPfD,RwuOMHCKErvcPs){jLXMEBNtNPfD.push(RwuOMHCKErvcPs);}" fullword ascii
    $s20 = "function pxZoOgYGWuJjyst(xhThVtVutsnDlXRzBcL) {return parseFloat(xhThVtVutsnDlXRzBcL);}" fullword ascii

  condition:
    uint16(0) == 0x4a50 and
    8 of them
}