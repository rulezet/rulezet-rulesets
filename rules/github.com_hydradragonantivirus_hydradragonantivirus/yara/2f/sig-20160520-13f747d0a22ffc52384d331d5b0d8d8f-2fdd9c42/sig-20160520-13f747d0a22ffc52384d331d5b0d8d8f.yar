rule sig_20160520_13f747d0a22ffc52384d331d5b0d8d8f {
  meta:
    description = "datamaliciousorder - file 20160520_13f747d0a22ffc52384d331d5b0d8d8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1c8c8866ba40fe36e4a7f8142eb11cc8e01e79075efcefadc21aed44553339a"

  strings:
    $s1  = "function OWgexhmA(YgNpp) {var wuOUjsRN=qEDFHzZvPBwCAVeRd[2];for(var ZsOrV=0;ZsOrV<YgNpp;ZsOrV++){FxEDS+=wuOUjsRN.charAt(Math.flo" ascii
    $s2  = "function OWgexhmA(YgNpp) {var wuOUjsRN=qEDFHzZvPBwCAVeRd[2];for(var ZsOrV=0;ZsOrV<YgNpp;ZsOrV++){FxEDS+=wuOUjsRN.charAt(Math.flo" ascii
    $s3  = "function HhPZG(KfhjOC){return new ActiveXObject(KfhjOC);}" fullword ascii
    $s4  = "nIwx, false);pLwPOvs.send();}" fullword ascii
    $s5  = "function ADapb(zanfsKer,UunRq,YMjsMaylDa){zanfsKer.open();zanfsKer.type = 1;zanfsKer.write(UunRq);zanfsKer.position = 0;zanfsKer" ascii
    $s6  = "or(Math.random()*wuOUjsRN.length));}return FxEDS;}" fullword ascii
    $s7  = "function ADapb(zanfsKer,UunRq,YMjsMaylDa){zanfsKer.open();zanfsKer.type = 1;zanfsKer.write(UunRq);zanfsKer.position = 0;zanfsKer" ascii
    $s8  = "d<NacKUR.length;auYZpmpd++) {nVSoghO+=LzBvL[NacKUR[auYZpmpd]];}return nVSoghO.substring(3,nVSoghO.length);}" fullword ascii
    $s9  = "function wFoFJFv() {var teDV=100000;var Hyyuij = 100;return Math.random()*(teDV-Hyyuij)+Hyyuij;}" fullword ascii
    $s10 = "try{VBVITIpjY(mZgxg[PYvf], wFoFJFv() + qEDFHzZvPBwCAVeRd[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function VBVITIpjY(sOBAdyYsO,WkRXoxQ,EfwGfzsg){" fullword ascii
    $s12 = "function vqXRhy(KfhjOC){return KfhjOC.ExpandEnvironmentStrings(qEDFHzZvPBwCAVeRd[10])}" fullword ascii
    $s13 = "function ehfmG(MgbbeAjl,NacKUR,ywdLPTtSS){LzBvL=MgbbeAjl.split(ywdLPTtSS);nVSoghO = qEDFHzZvPBwCAVeRd[13];for(auYZpmpd=0;auYZpmp" ascii
    $s14 = "function ehfmG(MgbbeAjl,NacKUR,ywdLPTtSS){LzBvL=MgbbeAjl.split(ywdLPTtSS);nVSoghO = qEDFHzZvPBwCAVeRd[13];for(auYZpmpd=0;auYZpmp" ascii
    $s15 = "function pGPm(NPnIwx,pLwPOvs){Dbko = qEDFHzZvPBwCAVeRd[11].split(qEDFHzZvPBwCAVeRd[12]);pLwPOvs.open(Dbko[0]+Dbko[2]+Dbko[3], NP" ascii
    $s16 = "function pGPm(NPnIwx,pLwPOvs){Dbko = qEDFHzZvPBwCAVeRd[11].split(qEDFHzZvPBwCAVeRd[12]);pLwPOvs.open(Dbko[0]+Dbko[2]+Dbko[3], NP" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}