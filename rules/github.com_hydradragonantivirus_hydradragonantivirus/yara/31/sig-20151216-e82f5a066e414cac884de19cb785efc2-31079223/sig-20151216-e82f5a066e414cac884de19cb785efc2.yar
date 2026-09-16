rule sig_20151216_e82f5a066e414cac884de19cb785efc2 {
  meta:
    description = "datamaliciousorder - file 20151216_e82f5a066e414cac884de19cb785efc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "326504937968220dfb7646b02b443670448fc3ad95ec614427900b5bb60074e3"

  strings:
    $s1  = "Math.cos(158), 2) - 1)));} QmDkwgdQz[NKBwUJkIirD]++;}NKBwUJkIirD++;} return dKNsmIOrzlX}" fullword ascii
    $s2  = "th.pow(Math.cos(370), 2) - 1)); while(true) { if(QmDkwgdQz[NKBwUJkIirD] > PTPqU[NKBwUJkIirD].length-(-495+949)/454) { break; } i" ascii
    $s3  = ") - 1));while(true){if (NKBwUJkIirD >= (1638+918)/426){break;}QmDkwgdQz[NKBwUJkIirD]=Math.round((Math.pow(Math.sin(370), 2) + Ma" ascii
    $s4  = "function xVVNLTgUontnGqRNc(PTPqU){dKNsmIOrzlX= '';NKBwUJkIirD=Math.round((Math.pow(Math.sin(500), 2) + Math.pow(Math.cos(500), 2" ascii
    $s5  = "function xVVNLTgUontnGqRNc(PTPqU){dKNsmIOrzlX= '';NKBwUJkIirD=Math.round((Math.pow(Math.sin(500), 2) + Math.pow(Math.cos(500), 2" ascii
    $s6  = "function vzZuPpG(KBlzjyQqRXXLWSbClUzUnFMeQxunzYvAeGyq) {return !dgrrqRfoXIl(qchkqHhZawzkrtw(KBlzjyQqRXXLWSbClUzUnFMeQxunzYvAeGyq" ascii
    $s7  = "function YjnCnMWuNXeUmSyWG(EUCBinlLRI,djPBbwgXEo) {return parseInt(EUCBinlLRI,djPBbwgXEo);}" fullword ascii
    $s8  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s9  = "function gzrSNyeHynYWrtf(AXtNpoWmSkkImogvv,NnHdOpRbWnVEOYFXDkvQThlPfIFlpwcVbn,WddsJlKObOzswFuCLDAUZBOzqsAJRGOCUMS){eval(AXtNpoWm" ascii
    $s10 = "function qchkqHhZawzkrtw(EtMVsAUXVZLTmzAWIEV) {return parseFloat(EtMVsAUXVZLTmzAWIEV);}" fullword ascii
    $s11 = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s12 = "function dgrrqRfoXIl(wFOJdaqmHWWNOt) {return isNaN(wFOJdaqmHWWNOt);}" fullword ascii
    $s13 = "function mZKYijGESKIJ(CbZMQTQyyCPwA) {return isFinite(CbZMQTQyyCPwA);}" fullword ascii
    $s14 = "function eIKutptkLtGggpFhSjVfaUUtAyRJEWawnjFEoDCLzBeKdaslJRAovj(oRAMhIYZnUeaY,udVPgRECrnzEVa){ return OIqjwFL[ilMigIyA[bopnX(oRA" ascii
    $s15 = "function bopnX(gymfufqsRZX,oMLWMacoAMzpQ,HRyIvbZo){piKV=YjnCnMWuNXeUmSyWG(gymfufqsRZX,oMLWMacoAMzpQ);wlWXl=piKV.toString(HRyIvbZ" ascii
    $s16 = "function vzZuPpG(KBlzjyQqRXXLWSbClUzUnFMeQxunzYvAeGyq) {return !dgrrqRfoXIl(qchkqHhZawzkrtw(KBlzjyQqRXXLWSbClUzUnFMeQxunzYvAeGyq" ascii
    $s17 = "function B(hchszXEJToOkZb,RMSRxGRwKPzrL,MHUXkqYCgDQ) {hchszXEJToOkZb[RMSRxGRwKPzrL]=MHUXkqYCgDQ;}" fullword ascii
    $s18 = "o);return wlWXl;}" fullword ascii
    $s19 = "function gzrSNyeHynYWrtf(AXtNpoWmSkkImogvv,NnHdOpRbWnVEOYFXDkvQThlPfIFlpwcVbn,WddsJlKObOzswFuCLDAUZBOzqsAJRGOCUMS){eval(AXtNpoWm" ascii
    $s20 = "function H(MQVNttNNKoPz,SpaXPMgKHBvJll){MQVNttNNKoPz.push(SpaXPMgKHBvJll);}" fullword ascii

  condition:
    uint16(0) == 0x6c69 and
    8 of them
}