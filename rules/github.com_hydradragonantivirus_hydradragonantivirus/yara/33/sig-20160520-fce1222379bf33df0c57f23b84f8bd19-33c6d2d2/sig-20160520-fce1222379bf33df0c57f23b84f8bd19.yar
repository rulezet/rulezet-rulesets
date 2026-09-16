rule sig_20160520_fce1222379bf33df0c57f23b84f8bd19 {
  meta:
    description = "datamaliciousorder - file 20160520_fce1222379bf33df0c57f23b84f8bd19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bcb59623618de0b4aa3e2222eebcdff9e3c9ac6430751f08ff1291551404015"

  strings:
    $s1  = "function ViGJEFyv(dRYEv) {var eXkldNLG=OvLqLhr[2];for(var ZmgiE=0;ZmgiE<dRYEv;ZmgiE++){NSZeh+=eXkldNLG.charAt(Math.floor(Math.ra" ascii
    $s2  = "function LmftptDve(hPJdhACKx,WRXJNUp,VmDKMdkH){" fullword ascii
    $s3  = "function ViGJEFyv(dRYEv) {var eXkldNLG=OvLqLhr[2];for(var ZmgiE=0;ZmgiE<dRYEv;ZmgiE++){NSZeh+=eXkldNLG.charAt(Math.floor(Math.ra" ascii
    $s4  = "try{LmftptDve(UXbmE[YXet], lJzsGiW() + OvLqLhr[9], 1)}catch(e){}; " fullword ascii
    $s5  = "function TTvtoD(RJHwnV){return RJHwnV.ExpandEnvironmentStrings(OvLqLhr[10])}" fullword ascii
    $s6  = "ndom()*eXkldNLG.length));}return NSZeh;}" fullword ascii
    $s7  = "function khQuF(aIVtRcgL,xVGsm,NAAZBsUeKo){aIVtRcgL.open();aIVtRcgL.type = 1;aIVtRcgL.write(xVGsm);aIVtRcgL.position = 0;aIVtRcgL" ascii
    $s8  = "function khQuF(aIVtRcgL,xVGsm,NAAZBsUeKo){aIVtRcgL.open();aIVtRcgL.type = 1;aIVtRcgL.write(xVGsm);aIVtRcgL.position = 0;aIVtRcgL" ascii
    $s9  = "function mOVzp(egehkZhT,qrGdjB,bRZupNxoV){XEaZy=egehkZhT.split(bRZupNxoV);WwHFcez = OvLqLhr[13];for(XQcRYPaB=0;XQcRYPaB<qrGdjB.l" ascii
    $s10 = "ength;XQcRYPaB++) {WwHFcez+=XEaZy[qrGdjB[XQcRYPaB]];}return WwHFcez.substring(3,WwHFcez.length);}" fullword ascii
    $s11 = "function MsnS(MiHkhq,SUHjrby){Fdkr = OvLqLhr[11].split(OvLqLhr[12]);SUHjrby.open(Fdkr[0]+Fdkr[2]+Fdkr[3], MiHkhq, false);SUHjrby" ascii
    $s12 = "function mOVzp(egehkZhT,qrGdjB,bRZupNxoV){XEaZy=egehkZhT.split(bRZupNxoV);WwHFcez = OvLqLhr[13];for(XQcRYPaB=0;XQcRYPaB<qrGdjB.l" ascii
    $s13 = "function MsnS(MiHkhq,SUHjrby){Fdkr = OvLqLhr[11].split(OvLqLhr[12]);SUHjrby.open(Fdkr[0]+Fdkr[2]+Fdkr[3], MiHkhq, false);SUHjrby" ascii
    $s14 = "function qZSGF(RJHwnV){return new ActiveXObject(RJHwnV);}" fullword ascii
    $s15 = "function lJzsGiW() {var cibp=100000;var aowPeY = 100;return Math.random()*(cibp-aowPeY)+aowPeY;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}