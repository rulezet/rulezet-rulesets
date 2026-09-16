rule sig_20151217_756649fabab62b199c139f5cc3a79613 {
  meta:
    description = "datamaliciousorder - file 20151217_756649fabab62b199c139f5cc3a79613.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd41bb4f64759e8db5f6590a3344ae0c9b6ea94bf7fcf7cd177bd239078a064d"

  strings:
    $s1  = "function uNxknHbNIfJCBNCqp(IaMGm){xdbTltUkkFA= '';CQDzPGoYEoE=Math.round((Math.pow(Math.sin(719), 2) + Math.pow(Math.cos(719), 2" ascii
    $s2  = ") - 1));while(true){if (CQDzPGoYEoE >= (5625+297)/987){break;}eHYzoVFUh[CQDzPGoYEoE]=Math.round((Math.pow(Math.sin(427), 2) + Ma" ascii
    $s3  = "(Math.cos(353), 2) - 1)));} eHYzoVFUh[CQDzPGoYEoE]++;}CQDzPGoYEoE++;} return xdbTltUkkFA}" fullword ascii
    $s4  = "th.pow(Math.cos(427), 2) - 1)); while(true) { if(eHYzoVFUh[CQDzPGoYEoE] > IaMGm[CQDzPGoYEoE].length-(360+202)/562) { break; } if" ascii
    $s5  = "function uNxknHbNIfJCBNCqp(IaMGm){xdbTltUkkFA= '';CQDzPGoYEoE=Math.round((Math.pow(Math.sin(719), 2) + Math.pow(Math.cos(719), 2" ascii
    $s6  = "function XlHiHtS(qJCMqwPOGCsdAUhvHtEmipaGPCQpsEvLlmBV) {return !RBgxkpMdxVO(XNUzgwScNzlxBrH(qJCMqwPOGCsdAUhvHtEmipaGPCQpsEvLlmBV" ascii
    $s7  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s8  = "function mfKTOVgQwLpmQSJVusDMzWMxHaCMCKDUxfTFvQKCOXfqTzByiIKJFG(REQpizsQaSUVI,pAJeJLwsAhdowE){ return UABPAiI[eOUZOBbH[jVIje(REQ" ascii
    $s9  = "function jVIje(mTisZUjkBfu,IUmXLRpmdZJss,XvrotWNo){yYOr=pruPPlRtosVxtIlmn(mTisZUjkBfu,IUmXLRpmdZJss);zPatC=yYOr.toString(XvrotWN" ascii
    $s10 = "function pruPPlRtosVxtIlmn(kpWSUqkvFs,sbdIDFZeOX) {return parseInt(kpWSUqkvFs,sbdIDFZeOX);}" fullword ascii
    $s11 = "function XlHiHtS(qJCMqwPOGCsdAUhvHtEmipaGPCQpsEvLlmBV) {return !RBgxkpMdxVO(XNUzgwScNzlxBrH(qJCMqwPOGCsdAUhvHtEmipaGPCQpsEvLlmBV" ascii
    $s12 = "function YiNTTxEujkMeJAA(OSLjGPHFGwTUdZXmW,pBAaGoEVYpXYSohvHWGRgsrgYiZXukRYcK,jCfHsxsAxjhmRUPINJRzeyKbEeSQZuExNLZ){eval(OSLjGPHF" ascii
    $s13 = "o);return zPatC;}" fullword ascii
    $s14 = "function i(FtczhumYOmLf,PuLgNnAJyMWszV){FtczhumYOmLf.push(PuLgNnAJyMWszV);}" fullword ascii
    $s15 = "function YiNTTxEujkMeJAA(OSLjGPHFGwTUdZXmW,pBAaGoEVYpXYSohvHWGRgsrgYiZXukRYcK,jCfHsxsAxjhmRUPINJRzeyKbEeSQZuExNLZ){eval(OSLjGPHF" ascii
    $s16 = "function mfKTOVgQwLpmQSJVusDMzWMxHaCMCKDUxfTFvQKCOXfqTzByiIKJFG(REQpizsQaSUVI,pAJeJLwsAhdowE){ return UABPAiI[eOUZOBbH[jVIje(REQ" ascii
    $s17 = "function zsyTJkqbnnjy(iBDOPaDmYnApZ) {return isFinite(iBDOPaDmYnApZ);}" fullword ascii
    $s18 = "function XNUzgwScNzlxBrH(okFqQqDbxHCHIzbPGsR) {return parseFloat(okFqQqDbxHCHIzbPGsR);}" fullword ascii
    $s19 = "function S(eTGdOjNlMidPSE,mdSbQxlqauwUq,ezBBYRYpAoe) {eTGdOjNlMidPSE[mdSbQxlqauwUq]=ezBBYRYpAoe;}" fullword ascii
    $s20 = "function jVIje(mTisZUjkBfu,IUmXLRpmdZJss,XvrotWNo){yYOr=pruPPlRtosVxtIlmn(mTisZUjkBfu,IUmXLRpmdZJss);zPatC=yYOr.toString(XvrotWN" ascii

  condition:
    uint16(0) == 0x4f65 and
    8 of them
}