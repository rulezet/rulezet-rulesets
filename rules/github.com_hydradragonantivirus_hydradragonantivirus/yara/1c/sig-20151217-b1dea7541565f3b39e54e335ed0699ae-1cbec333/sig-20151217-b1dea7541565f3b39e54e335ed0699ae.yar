rule sig_20151217_b1dea7541565f3b39e54e335ed0699ae {
  meta:
    description = "datamaliciousorder - file 20151217_b1dea7541565f3b39e54e335ed0699ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c20ff8de80e55b3bc1a6786ebefc2be8cef56d9fd5f9a820c6135e01b9ab2a13"

  strings:
    $s1  = "(Math.cos(393), 2) - 1)));} aebSrAJQs[WpIawONFnMC]++;}WpIawONFnMC++;} return JNetTBMoZRD}" fullword ascii
    $s2  = ".pow(Math.cos(521), 2) - 1)); while(true) { if(aebSrAJQs[WpIawONFnMC] > Qendu[WpIawONFnMC].length-(-121+314)/193) { break; } if " ascii
    $s3  = "function MaCPaNpUHJtCQXpfa(Qendu){JNetTBMoZRD= '';WpIawONFnMC=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s4  = "- 1));while(true){if (WpIawONFnMC >= (5184+480)/944){break;}aebSrAJQs[WpIawONFnMC]=Math.round((Math.pow(Math.sin(521), 2) + Math" ascii
    $s5  = "function MaCPaNpUHJtCQXpfa(Qendu){JNetTBMoZRD= '';WpIawONFnMC=Math.round((Math.pow(Math.sin(53), 2) + Math.pow(Math.cos(53), 2) " ascii
    $s6  = "function QSQrDkv(kdDuVdeqGvARALwqVxmZOrbpdMDVybbrEVmA) {return !PbfTusFjoNH(YNJhveZhFnLRijq(kdDuVdeqGvARALwqVxmZOrbpdMDVybbrEVmA" ascii
    $s7  = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s8  = "function rXyvxmlZaGNL(rXWcvdlGbfqds) {return isFinite(rXWcvdlGbfqds);}" fullword ascii
    $s9  = "function PbfTusFjoNH(uxQISmKzxBzZag) {return isNaN(uxQISmKzxBzZag);}" fullword ascii
    $s10 = ",'R','V','\"',')','+','V','7','W','f','=','X','O','U','c','Y','+','Y','U','a','z','{','Z','P','k','7','>','r','[','a','@',String" ascii
    $s11 = "function MLJcp(GDhuawjcoJo,JpQgbVwsxKxUt,dRDbaSvQ){Doki=KtZxaeRnPmzkCDfwd(GDhuawjcoJo,JpQgbVwsxKxUt);cfPyW=Doki.toString(dRDbaSv" ascii
    $s12 = "function ZrdoSXRQBYEPNFLIRigjWmVyRIonXKIhtdhwXkRRFPTAHmrUWyqhGX(WAbGSBjamSilB,PdazvDOYAfOADG){ return pSLMMuJ[ADmjPGXc[MLJcp(WAb" ascii
    $s13 = "var b = new Array();b[0]=[];b[0][0]='d';b[0][1]='a';b[0][2]='d';b[0][3]='a';b[0][4]='46';b[0][5]='3d';b[0][6]='42';b[0][7]='14';" ascii
    $s14 = "function QSQrDkv(kdDuVdeqGvARALwqVxmZOrbpdMDVybbrEVmA) {return !PbfTusFjoNH(YNJhveZhFnLRijq(kdDuVdeqGvARALwqVxmZOrbpdMDVybbrEVmA" ascii
    $s15 = "function KtZxaeRnPmzkCDfwd(rfWvdXMjSp,vLVmsofibn) {return parseInt(rfWvdXMjSp,vLVmsofibn);}" fullword ascii
    $s16 = "Q);return cfPyW;}" fullword ascii
    $s17 = "function ZrdoSXRQBYEPNFLIRigjWmVyRIonXKIhtdhwXkRRFPTAHmrUWyqhGX(WAbGSBjamSilB,PdazvDOYAfOADG){ return pSLMMuJ[ADmjPGXc[MLJcp(WAb" ascii
    $s18 = "function T(KYYWDZivqnBfvR,eqWiAkIBGmnfN,WyAwAXBxsmS) {KYYWDZivqnBfvR[eqWiAkIBGmnfN]=WyAwAXBxsmS;}" fullword ascii
    $s19 = "function YNJhveZhFnLRijq(UsonSNFVLxJWaLbLesh) {return parseFloat(UsonSNFVLxJWaLbLesh);}" fullword ascii
    $s20 = "function MLJcp(GDhuawjcoJo,JpQgbVwsxKxUt,dRDbaSvQ){Doki=KtZxaeRnPmzkCDfwd(GDhuawjcoJo,JpQgbVwsxKxUt);cfPyW=Doki.toString(dRDbaSv" ascii

  condition:
    uint16(0) == 0x4441 and
    8 of them
}