rule sig_20160520_5dcc2bd67d40869c79aa31adcf6b43bf {
  meta:
    description = "datamaliciousorder - file 20160520_5dcc2bd67d40869c79aa31adcf6b43bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17b4665d3a8aeafe74c4ceb94454b396b5a0817dc047f56a88f148f30b171aa4"

  strings:
    $s1  = "function iVwSQPqu(yxZDE) {var YImhZeME=hPraihApNTBzzdNAUjp[2];for(var DxVWq=0;DxVWq<yxZDE;DxVWq++){zgFpv+=YImhZeME.charAt(Math.f" ascii
    $s2  = "function iVwSQPqu(yxZDE) {var YImhZeME=hPraihApNTBzzdNAUjp[2];for(var DxVWq=0;DxVWq<yxZDE;DxVWq++){zgFpv+=YImhZeME.charAt(Math.f" ascii
    $s3  = "function xsWqOSnlA(bdVUZnqiM,CMdfUNr,wNyjCgyr){" fullword ascii
    $s4  = "try{ElUyAvc=xsWqOSnlA(Gaxfr[Enpd], tHXaRZF() + hPraihApNTBzzdNAUjp[9], 1)}catch(e){}; " fullword ascii
    $s5  = "CsE<UOxdfU.length;MhHPwCsE++) {WmiPtgT+=BhJgT[UOxdfU[MhHPwCsE]];}return WmiPtgT.substring(3,WmiPtgT.length);}" fullword ascii
    $s6  = ", BuvVXL, false);JbGeZba.send();}" fullword ascii
    $s7  = "function tHXaRZF() {var UkyJ=100000;var KSBmHG = 100;return Math.random()*(UkyJ-KSBmHG)+KSBmHG;}" fullword ascii
    $s8  = "function uBys(BuvVXL,JbGeZba){DDOd = hPraihApNTBzzdNAUjp[11].split(hPraihApNTBzzdNAUjp[12]);JbGeZba.open(DDOd[0]+DDOd[2]+DDOd[3]" ascii
    $s9  = "function uBys(BuvVXL,JbGeZba){DDOd = hPraihApNTBzzdNAUjp[11].split(hPraihApNTBzzdNAUjp[12]);JbGeZba.open(DDOd[0]+DDOd[2]+DDOd[3]" ascii
    $s10 = "function SWHdi(qwtYaARM,dfoxg,WdDlkbdZHA){qwtYaARM.open();qwtYaARM.type = 1;qwtYaARM.write(dfoxg);qwtYaARM.position = 0;qwtYaARM" ascii
    $s11 = "loor(Math.random()*YImhZeME.length));}return zgFpv;}" fullword ascii
    $s12 = "function SWHdi(qwtYaARM,dfoxg,WdDlkbdZHA){qwtYaARM.open();qwtYaARM.type = 1;qwtYaARM.write(dfoxg);qwtYaARM.position = 0;qwtYaARM" ascii
    $s13 = "function fkqUb(tXAiLQ){return new ActiveXObject(tXAiLQ);}" fullword ascii
    $s14 = "function FVLaud(tXAiLQ){return tXAiLQ.ExpandEnvironmentStrings(hPraihApNTBzzdNAUjp[10])}" fullword ascii
    $s15 = "if (ElUyAvc==0) break;" fullword ascii
    $s16 = "function chBsE(hwVHDQkA,UOxdfU,sHInieAzD){BhJgT=hwVHDQkA.split(sHInieAzD);WmiPtgT = hPraihApNTBzzdNAUjp[13];for(MhHPwCsE=0;MhHPw" ascii
    $s17 = "function chBsE(hwVHDQkA,UOxdfU,sHInieAzD){BhJgT=hwVHDQkA.split(sHInieAzD);WmiPtgT = hPraihApNTBzzdNAUjp[13];for(MhHPwCsE=0;MhHPw" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}