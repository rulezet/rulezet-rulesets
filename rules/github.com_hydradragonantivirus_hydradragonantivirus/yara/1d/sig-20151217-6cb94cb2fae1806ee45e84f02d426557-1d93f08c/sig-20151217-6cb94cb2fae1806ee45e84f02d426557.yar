rule sig_20151217_6cb94cb2fae1806ee45e84f02d426557 {
  meta:
    description = "datamaliciousorder - file 20151217_6cb94cb2fae1806ee45e84f02d426557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd4b4e9dc3eddd6528d5efb4da9934099277414c55d6e3b642509b64457af7ea"

  strings:
    $s1  = "function uljhoUSfOPoOJASNu(jkMJQ){FjAupyQiGnY= '';umqblWYwtUV=Math.round((Math.pow(Math.sin(720), 2) + Math.pow(Math.cos(720), 2" ascii
    $s2  = ") - 1));while(true){if (umqblWYwtUV >= (2507+409)/486){break;}SsmvCvmzv[umqblWYwtUV]=Math.round((Math.pow(Math.sin(955), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(955), 2) - 1)); while(true) { if(SsmvCvmzv[umqblWYwtUV] > jkMJQ[umqblWYwtUV].length-(62+896)/958) { break; } if " ascii
    $s4  = "(Math.cos(20), 2) - 1)));} SsmvCvmzv[umqblWYwtUV]++;}umqblWYwtUV++;} return FjAupyQiGnY}" fullword ascii
    $s5  = "function uljhoUSfOPoOJASNu(jkMJQ){FjAupyQiGnY= '';umqblWYwtUV=Math.round((Math.pow(Math.sin(720), 2) + Math.pow(Math.cos(720), 2" ascii
    $s6  = "function qCUpQjh(sHttQQoKLIiLTsGxCQtoulOiydfYdULsRCWh) {return !aKXWLHZxdFU(pyPUNNVyFzSkokE(sHttQQoKLIiLTsGxCQtoulOiydfYdULsRCWh" ascii
    $s7  = "function wbwQJSsrgCbVlRuizznsMtLVExQYbLWHMPnsRaCXtciGtxSFGiFnGw(GMVUiAceAGNtr,ibGQyRhpbbEfSd){ return NbYmtol[LYxGPIVh[jyQfd(GMV" ascii
    $s8  = "function wbwQJSsrgCbVlRuizznsMtLVExQYbLWHMPnsRaCXtciGtxSFGiFnGw(GMVUiAceAGNtr,ibGQyRhpbbEfSd){ return NbYmtol[LYxGPIVh[jyQfd(GMV" ascii
    $s9  = "function M(AAxtvmIrDMrvEy,QbpfOmQhsszjP,GXpsxIQGjcI) {AAxtvmIrDMrvEy[QbpfOmQhsszjP]=GXpsxIQGjcI;}" fullword ascii
    $s10 = "function jyQfd(lgxnmpONbRO,ZocxIXvrgXbRs,ASLiAcOZ){MJqd=LgylhiTLNYSpvyPVa(lgxnmpONbRO,ZocxIXvrgXbRs);dgUuu=MJqd.toString(ASLiAcO" ascii
    $s11 = "function pyPUNNVyFzSkokE(heEyttmECqVblDuRgLs) {return parseFloat(heEyttmECqVblDuRgLs);}" fullword ascii
    $s12 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s13 = "function WWUiUJctFOiDqAe(hGoSenLzTChYdGJMD,bIEcyJLRvKYISNOUHqTiIfAnPWLHraNgaq,ZCQGGXXwYqZkRKwAmbvMeqharZfZMkwNyDP){eval(hGoSenLz" ascii
    $s14 = ",']','#','V','Q','W','k','L','6','a','X','1','^','m','q','G','Y','4','q','B','!','X','R','5','Z','+','[',':','K','M','\"',String" ascii
    $s15 = "Z);return dgUuu;}" fullword ascii
    $s16 = "function WWUiUJctFOiDqAe(hGoSenLzTChYdGJMD,bIEcyJLRvKYISNOUHqTiIfAnPWLHraNgaq,ZCQGGXXwYqZkRKwAmbvMeqharZfZMkwNyDP){eval(hGoSenLz" ascii
    $s17 = "function jyQfd(lgxnmpONbRO,ZocxIXvrgXbRs,ASLiAcOZ){MJqd=LgylhiTLNYSpvyPVa(lgxnmpONbRO,ZocxIXvrgXbRs);dgUuu=MJqd.toString(ASLiAcO" ascii
    $s18 = "function qCUpQjh(sHttQQoKLIiLTsGxCQtoulOiydfYdULsRCWh) {return !aKXWLHZxdFU(pyPUNNVyFzSkokE(sHttQQoKLIiLTsGxCQtoulOiydfYdULsRCWh" ascii
    $s19 = "function U(OvQvrdchTNaK,dWXqqqXObSLRxO){OvQvrdchTNaK.push(dWXqqqXObSLRxO);}" fullword ascii
    $s20 = "function aKXWLHZxdFU(YgabCYRDjTuhcn) {return isNaN(YgabCYRDjTuhcn);}" fullword ascii

  condition:
    uint16(0) == 0x594c and
    8 of them
}