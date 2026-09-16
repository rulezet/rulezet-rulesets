rule sig_20160527_7dee5bcf7a7980b49d88c042e3f437ac {
  meta:
    description = "datamaliciousorder - file 20160527_7dee5bcf7a7980b49d88c042e3f437ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b65101a2b91497be527ebf1abf374b2ed87bc27cf7813b8f2fb64f1bf6ed26"

  strings:
    $s1  = "function RmmeJ() {return WScript;}function TtORHzwyyNfsx(){return ClsScUVw.ExpandEnvironmentStrings(XPAnFvoRglSNE())}" fullword ascii
    $s2  = "function UBkgprP(eeDkAH,cmSxkqQGAt){return eeDkAH.charAt(cmSxkqQGAt);}" fullword ascii
    $s3  = "elpBg = WhIOeezmQpPBPKrIkIbMvDQ & 0xff;if (MvAGpkOK == 64) mHyQEvTaTK += X(fdJpzoLV);else if (UuCMMcJyQpZZOPLVo == 64) mHyQEvTaT" ascii
    $s4  = "function ZzVLtyiKiPOe(WlAubXNKfAonE) {var McMUKMCprWIebGBom = SUOoDRCzcdIuxzerABilgqeo.join(RzthfDW[6]);var fdJpzoLV, EFbyUKHAHi" ascii
    $s5  = "K += aLosXukrWCKKEFZB(fdJpzoLV, EFbyUKHAHikQ);else mHyQEvTaTK += aiiRlHglgxPcknABmtc(fdJpzoLV, EFbyUKHAHikQ, LelpBg);} while (sL" ascii
    $s6  = "function sQOnLS(SjIBCPJvpa,hQOUTvSNsDJwaQ,obymMJ){SMxtDyaPE=SjIBCPJvpa.split(obymMJ);ywXUixuf = RzthfDW[14];for(uGHWTZo=0;uGHWTZ" ascii
    $s7  = "var jxLRwQHNC=function(){return new ActiveXObject(RzthfDW[0]);}();" fullword ascii
    $s8  = "function yYhtSguQWyg(){return sQOnLS(RzthfDW[12],[0,3,6],RzthfDW[13]);}" fullword ascii
    $s9  = "function X(eTfRZnYHhyiIaJiwvrWuzXN){return String.fromCharCode(eTfRZnYHhyiIaJiwvrWuzXN);}" fullword ascii
    $s10 = "QSBsECbPpvMA < WlAubXNKfAonE.length);return mHyQEvTaTK;}" fullword ascii
    $s11 = "function XPAnFvoRglSNE(){return sQOnLS(RzthfDW[8],[1,5,7],RzthfDW[9]);}" fullword ascii
    $s12 = "var ClsScUVw=function(){return RmmeJ().CreateObject(RzthfDW[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "zthfDW[4],true);" fullword ascii
    $s14 = "function sQOnLS(SjIBCPJvpa,hQOUTvSNsDJwaQ,obymMJ){SMxtDyaPE=SjIBCPJvpa.split(obymMJ);ywXUixuf = RzthfDW[14];for(uGHWTZo=0;uGHWTZ" ascii
    $s15 = "function aiiRlHglgxPcknABmtc(wcmRKITBYYplFtd,pPUhHhBXFpBURcHNpiljeN,kgxlWRwyQJaxCZjNSA){return String.fromCharCode(wcmRKITBYYplF" ascii
    $s16 = "push(\"v\");SUOoDRCzcdIuxzerABilgqeo.push(\"w\");SUOoDRCzcdIuxzerABilgqeo.push(\"x\");SUOoDRCzcdIuxzerABilgqeo.push(\"y\");SUOoD" ascii
    $s17 = "function ZzVLtyiKiPOe(WlAubXNKfAonE) {var McMUKMCprWIebGBom = SUOoDRCzcdIuxzerABilgqeo.join(RzthfDW[6]);var fdJpzoLV, EFbyUKHAHi" ascii
    $s18 = "function aLosXukrWCKKEFZB(lFQQGMN,VXGDhwPlgscwWiFoWAExNeVH){return String.fromCharCode(lFQQGMN,VXGDhwPlgscwWiFoWAExNeVH);}" fullword ascii
    $s19 = "function iWkPI(){return sQOnLS(RzthfDW[10],[2,4,8,10],RzthfDW[11]);}" fullword ascii
    $s20 = "function aiiRlHglgxPcknABmtc(wcmRKITBYYplFtd,pPUhHhBXFpBURcHNpiljeN,kgxlWRwyQJaxCZjNSA){return String.fromCharCode(wcmRKITBYYplF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}