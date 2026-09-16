rule sig_20151209_201594ee474f01df6d90c60f61203bfe {
  meta:
    description = "datamaliciousorder - file 20151209_201594ee474f01df6d90c60f61203bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d8124644ee0c6f338fe7435c3720fdde1a08830321e40822de0f95632ca62d"

  strings:
    $s1  = "function yYPPumZRrYwobInDA(iyCgL){RDSbhHIKYBZ= '';for(aYxXcoEagVD=(-232+232)/203; aYxXcoEagVD < (-208+474)/133; aYxXcoEagVD++) {" ascii
    $s2  = "function yYPPumZRrYwobInDA(iyCgL){RDSbhHIKYBZ= '';for(aYxXcoEagVD=(-232+232)/203; aYxXcoEagVD < (-208+474)/133; aYxXcoEagVD++) {" ascii
    $s3  = "function BIgdsnT(FjMRgjLcSsEfeKosWhjWqdmdaqRQTUabkDlT) {return !isNaN(parseFloat(FjMRgjLcSsEfeKosWhjWqdmdaqRQTUabkDlT)) && isFin" ascii
    $s4  = "function BIgdsnT(FjMRgjLcSsEfeKosWhjWqdmdaqRQTUabkDlT) {return !isNaN(parseFloat(FjMRgjLcSsEfeKosWhjWqdmdaqRQTUabkDlT)) && isFin" ascii
    $s5  = "function ehQWqOjdmFx(swQvovcY,ByiOPE){return swQvovcY.split(ByiOPE)}" fullword ascii
    $s6  = "+;}} return RDSbhHIKYBZ}" fullword ascii
    $s7  = "function XnoDtcUutivSwTkOpjoXoycTcblawDYEaIJuLGkRaGlemfYgBNYNji(IiPlCGagVyyft,eoLMoEYJYCjoFX){ return lHJyz[uVXMa(IiPlCGagVyyft[" ascii
    $s8  = " uKOok;}function OAwgKsoEaJFjplA(JCheRpklxVyyBxRig){eval(JCheRpklxVyyBxRig)}" fullword ascii
    $s9  = "function XnoDtcUutivSwTkOpjoXoycTcblawDYEaIJuLGkRaGlemfYgBNYNji(IiPlCGagVyyft,eoLMoEYJYCjoFX){ return lHJyz[uVXMa(IiPlCGagVyyft[" ascii
    $s10 = "YobTsMOng[aYxXcoEagVD]=(-701+701)/97; while(true) { if(YobTsMOng[aYxXcoEagVD] > iyCgL[aYxXcoEagVD].length-(335+429)/764) { break" ascii
    $s11 = "function uVXMa(QxqtPWTGwkc,JrnIdpnBhwtSW,OaLehoxV){FgiY=parseInt(QxqtPWTGwkc,JrnIdpnBhwtSW);uKOok=FgiY.toString(OaLehoxV);return" ascii
    $s12 = "function uVXMa(QxqtPWTGwkc,JrnIdpnBhwtSW,OaLehoxV){FgiY=parseInt(QxqtPWTGwkc,JrnIdpnBhwtSW);uKOok=FgiY.toString(OaLehoxV);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}