rule sig_20160527_4a2e4d77244aa6ade9a8b67d6cc3151f {
  meta:
    description = "datamaliciousorder - file 20160527_4a2e4d77244aa6ade9a8b67d6cc3151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64226c8a60a837469d77815848f86107008d94eb671ba141242e5d0dcc109be8"

  strings:
    $s1  = "function XfvPjZbIjTwzIn() {return WScript;}function jBtYwJYUC(){return ZCRVwIuecM.ExpandEnvironmentStrings(LFQsGdGvvBxYVC())}" fullword ascii
    $s2  = "function aagPaXdKhtIFbJ(kpuFEFXANjHktlAo,ZQjXNMaXYXWi){return kpuFEFXANjHktlAo.charAt(ZQjXNMaXYXWi);}" fullword ascii
    $s3  = "GtBrcCooEJNBs.length);return fMofY;}" fullword ascii
    $s4  = "var RAOtg = wcQWOyILCv.createtextfile(ZCRVwIuecM.ExpandEnvironmentStrings(nbwJcITKuhJMwY[2]+nbwJcITKuhJMwY[3])+String.fromCharCo" ascii
    $s5  = "function BUQEkcEkRXHqaD(){return shsQtl(nbwJcITKuhJMwY[12],[0,3,6],nbwJcITKuhJMwY[13]);}" fullword ascii
    $s6  = "function tLVqZwkuVNhlT(GtBrcCooEJNBs) {var aisnzOugZIcfwBipz = oBIcjXzkuMVKmSADaGfex.join(nbwJcITKuhJMwY[6]);var BFnoLQEKtmFRhlj" ascii
    $s7  = "var ZCRVwIuecM=function(){return XfvPjZbIjTwzIn().CreateObject(nbwJcITKuhJMwY[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "wlysP);else fMofY += dnQfzR(BFnoLQEKtmFRhljoICLUPZKm, urGDFuIjwlysP, oEHHVJWmipQDshNRkORtTu);} while (gCtTfOkGEvnqaSahIPZWlZu < " ascii
    $s9  = "function uwwuyy(vNGFGQbAlf,NUGeuQm) {var HOYhLp=[nbwJcITKuhJMwY[15]];vNGFGQbAlf[HOYhLp[0]](NUGeuQm,0x1,0x0)}" fullword ascii
    $s10 = "de(92)+nbwJcITKuhJMwY[4],true);" fullword ascii
    $s11 = "function tLVqZwkuVNhlT(GtBrcCooEJNBs) {var aisnzOugZIcfwBipz = oBIcjXzkuMVKmSADaGfex.join(nbwJcITKuhJMwY[6]);var BFnoLQEKtmFRhlj" ascii
    $s12 = "function JQVMoXDqCONwuhE(ThMjjkbBGDXSLhtKBrJao,hWymTgErWyTWIndAQZO){return ThMjjkbBGDXSLhtKBrJao.indexOf(hWymTgErWyTWIndAQZO);}" fullword ascii
    $s13 = "(BFnoLQEKtmFRhljoICLUPZKm);else if (ZSOzgZyEZUoWxEpJC == 64) fMofY += xTbeFlLKlKKBrAcIPHewGzH(BFnoLQEKtmFRhljoICLUPZKm, urGDFuIj" ascii
    $s14 = "var wcQWOyILCv=function(){return new ActiveXObject(nbwJcITKuhJMwY[0]);}();" fullword ascii
    $s15 = "function LFQsGdGvvBxYVC(){return shsQtl(nbwJcITKuhJMwY[8],[1,5,7],nbwJcITKuhJMwY[9]);}" fullword ascii
    $s16 = "function xPoRH(){return shsQtl(nbwJcITKuhJMwY[10],[2,4,8,10],nbwJcITKuhJMwY[11]);}" fullword ascii
    $s17 = "function dnQfzR(dGYjsCHVzlTJF,qJcCyMJp,KYMfgHoAtLcp){return String.fromCharCode(dGYjsCHVzlTJF,qJcCyMJp,KYMfgHoAtLcp);}" fullword ascii
    $s18 = "function kX(xgbPPyUcxrRuawpgPfir){return String.fromCharCode(xgbPPyUcxrRuawpgPfir);}" fullword ascii
    $s19 = "N.length;XZxfu++) {WdmcameJhP+=umpTb[XaBJN[XZxfu]];}return WdmcameJhP.substring(3,WdmcameJhP.length);}" fullword ascii
    $s20 = "function xTbeFlLKlKKBrAcIPHewGzH(OyPROBVeIHTAZ,lmpvyrRsGBmLGUGcAdPZXBuY){return String.fromCharCode(OyPROBVeIHTAZ,lmpvyrRsGBmLGU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}