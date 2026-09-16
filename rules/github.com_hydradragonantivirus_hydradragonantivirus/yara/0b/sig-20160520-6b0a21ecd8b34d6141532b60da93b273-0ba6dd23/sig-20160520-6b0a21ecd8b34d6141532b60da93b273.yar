rule sig_20160520_6b0a21ecd8b34d6141532b60da93b273 {
  meta:
    description = "datamaliciousorder - file 20160520_6b0a21ecd8b34d6141532b60da93b273.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c161a396d256c4e2ca872de322a974d57b2402aca9945ffae564a5f7999e3f0"

  strings:
    $s1  = "function lKJMzLpw(pQPFh) {var gsdYlLjo=mTwKwKFr[2];for(var kePbH=0;kePbH<pQPFh;kePbH++){kmIIm+=gsdYlLjo.charAt(Math.floor(Math.r" ascii
    $s2  = "function lKJMzLpw(pQPFh) {var gsdYlLjo=mTwKwKFr[2];for(var kePbH=0;kePbH<pQPFh;kePbH++){kmIIm+=gsdYlLjo.charAt(Math.floor(Math.r" ascii
    $s3  = "function fhETb(JftZQaQz,IydzO,mxxpBRrObD){JftZQaQz.open();JftZQaQz.type = 1;JftZQaQz.write(IydzO);JftZQaQz.position = 0;JftZQaQz" ascii
    $s4  = "try{iOSYTCx=zcoEzlCQK(IUYSM[nenx], CXoSgHQ() + mTwKwKFr[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function rlivT(WRSLIqel,RIrkxy,qaYTmztvR){YYzsG=WRSLIqel.split(qaYTmztvR);CGQIruc = mTwKwKFr[13];for(afmruhUw=0;afmruhUw<RIrkxy." ascii
    $s6  = "function fhETb(JftZQaQz,IydzO,mxxpBRrObD){JftZQaQz.open();JftZQaQz.type = 1;JftZQaQz.write(IydzO);JftZQaQz.position = 0;JftZQaQz" ascii
    $s7  = "length;afmruhUw++) {CGQIruc+=YYzsG[RIrkxy[afmruhUw]];}return CGQIruc.substring(3,CGQIruc.length);}" fullword ascii
    $s8  = "andom()*gsdYlLjo.length));}return kmIIm;}" fullword ascii
    $s9  = "function wJlGR(dhFplE){return new ActiveXObject(dhFplE);}" fullword ascii
    $s10 = "if (iOSYTCx==0) break;" fullword ascii
    $s11 = "function CXoSgHQ() {var mwbf=100000;var FQDkjh = 100;return Math.random()*(mwbf-FQDkjh)+FQDkjh;}" fullword ascii
    $s12 = "function HqZy(qBgTRz,HIiPoiO){DlkG = mTwKwKFr[11].split(mTwKwKFr[12]);HIiPoiO.open(DlkG[0]+DlkG[2]+DlkG[3], qBgTRz, false);HIiPo" ascii
    $s13 = "function ghDIwm(dhFplE){return dhFplE.ExpandEnvironmentStrings(mTwKwKFr[10])}" fullword ascii
    $s14 = "function HqZy(qBgTRz,HIiPoiO){DlkG = mTwKwKFr[11].split(mTwKwKFr[12]);HIiPoiO.open(DlkG[0]+DlkG[2]+DlkG[3], qBgTRz, false);HIiPo" ascii
    $s15 = "function zcoEzlCQK(GOWPBUDHa,HzjWbsh,GzkMVbIK){" fullword ascii
    $s16 = "function rlivT(WRSLIqel,RIrkxy,qaYTmztvR){YYzsG=WRSLIqel.split(qaYTmztvR);CGQIruc = mTwKwKFr[13];for(afmruhUw=0;afmruhUw<RIrkxy." ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}