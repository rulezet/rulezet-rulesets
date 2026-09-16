rule sig_20160523_c51c04540b3c016e76a423ae96400359 {
  meta:
    description = "datamaliciousorder - file 20160523_c51c04540b3c016e76a423ae96400359.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf589f4dac1b35d7151be97940ca7220b2eed4979e161b127ff4f296d2321ed9"

  strings:
    $s1  = "function dptDautptY(fTHfOfPv,htoYtzdtlRHL) {fTHfOfPv.Run(htoYtzdtlRHL, 0x1, 0x0);}" fullword ascii
    $s2  = "function MBRblyYc(RIRMi) {var SPEqmJDU=NPyjZODsJHTOdWLZ[2];for(var CRgYZ=0;CRgYZ<RIRMi;CRgYZ++){fnhoR+=SPEqmJDU.charAt(Math.floo" ascii
    $s3  = "function MBRblyYc(RIRMi) {var SPEqmJDU=NPyjZODsJHTOdWLZ[2];for(var CRgYZ=0;CRgYZ<RIRMi;CRgYZ++){fnhoR+=SPEqmJDU.charAt(Math.floo" ascii
    $s4  = "ls, false);PrPxNCr.send();}" fullword ascii
    $s5  = "r(Math.random()*SPEqmJDU.length));}return fnhoR;}" fullword ascii
    $s6  = "function hzbN(cOSdls,PrPxNCr){NbiX = NPyjZODsJHTOdWLZ[11].split(NPyjZODsJHTOdWLZ[12]);PrPxNCr.open(NbiX[0]+NbiX[2]+NbiX[3], cOSd" ascii
    $s7  = "function auEpB(MZXJSHQc,wTqMM,CxrwYIWPbX){hUGD(MZXJSHQc);byZNYRlF(MZXJSHQc);qPIiUbI(MZXJSHQc,wTqMM);nRwqCCdMA(MZXJSHQc);BAtb(MZX" ascii
    $s8  = "<yvsjWL.length;mMkDLinf++) {zPBkfkF+=Iccyz[yvsjWL[mMkDLinf]];}return zPBkfkF.substring(3,zPBkfkF.length);}" fullword ascii
    $s9  = "try{kWKjoPu=CIRBjKaKl(sgzHn[ukaC], SMCsYGG() + NPyjZODsJHTOdWLZ[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function nRwqCCdMA(vmalJO) {var epdaxPOQcr=[];vmalJO.position=epdaxPOQcr.length*(161826-992);}" fullword ascii
    $s11 = "function CIRBjKaKl(bBrekbNHJ,tPwXIIn,XzdyjXmX){" fullword ascii
    $s12 = "function auEpB(MZXJSHQc,wTqMM,CxrwYIWPbX){hUGD(MZXJSHQc);byZNYRlF(MZXJSHQc);qPIiUbI(MZXJSHQc,wTqMM);nRwqCCdMA(MZXJSHQc);BAtb(MZX" ascii
    $s13 = "function hUGD(wAMvyr) {wAMvyr.open();}" fullword ascii
    $s14 = "function qPIiUbI(VOBQ,GbDXn) {VOBQ.write(GbDXn);}" fullword ascii
    $s15 = "function SMCsYGG() {var XWoe=100000;var WKoHFM = 100;return CFKvKMt()*(XWoe-WKoHFM)+WKoHFM;}" fullword ascii
    $s16 = "function byZNYRlF(BgTmkviyV) {BgTmkviyV.type=1;}" fullword ascii
    $s17 = "function hzbN(cOSdls,PrPxNCr){NbiX = NPyjZODsJHTOdWLZ[11].split(NPyjZODsJHTOdWLZ[12]);PrPxNCr.open(NbiX[0]+NbiX[2]+NbiX[3], cOSd" ascii
    $s18 = "function XFQoSl(gZerUP){return gZerUP.ExpandEnvironmentStrings(NPyjZODsJHTOdWLZ[10])}" fullword ascii
    $s19 = "if (kWKjoPu==0) break;" fullword ascii
    $s20 = "function BAtb(BWtvBxC,HLURoRG) {BWtvBxC.saveToFile(HLURoRG, 2);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}