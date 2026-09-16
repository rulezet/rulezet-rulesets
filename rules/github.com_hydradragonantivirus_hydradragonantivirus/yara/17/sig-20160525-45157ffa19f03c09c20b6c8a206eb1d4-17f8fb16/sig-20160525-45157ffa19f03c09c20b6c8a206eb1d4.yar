rule sig_20160525_45157ffa19f03c09c20b6c8a206eb1d4 {
  meta:
    description = "datamaliciousorder - file 20160525_45157ffa19f03c09c20b6c8a206eb1d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ced71279efac96b7e139037bccdc494f8437ad308401c078eb30b04e441526ce"

  strings:
    $s1  = "s(232), 2) - 1))-50)) LUGoefWcuQH += ld(uTSnMVUNpNNgnLKOohGoMSOy);else if (fRLXXvoEoISQdElfKbaRHL == (306 + Math.round((Math.pow" ascii
    $s2  = "function PXNCtYfKNfnCXx(HdSydxVooiKkJ) {var LyToabPtQI = abMvrthtqtsPi.join(zDsxOQIkHaCAD[0]);var uTSnMVUNpNNgnLKOohGoMSOy, xrzK" ascii
    $s3  = "function HUuNlfZyCGMmqDEsP(CbnetxhbNMSafarxztk,DYvzqcLUcJuQTgSvpR){return CbnetxhbNMSafarxztk.charAt(DYvzqcLUcJuQTgSvpR);}" fullword ascii
    $s4  = "KkJ.length);return LUGoefWcuQH;}" fullword ascii
    $s5  = "else LUGoefWcuQH += dOmcbJeqWYrNIJzRmDBwKtPt(uTSnMVUNpNNgnLKOohGoMSOy, xrzKlbcBdHP, KFzpoYUrWLJ);} while (ISESDASJV < HdSydxVooi" ascii
    $s6  = "function mXSXCKuFgEPfJ(chnYjlv,AEgfzbmhpRtFf){return String.fromCharCode(chnYjlv,AEgfzbmhpRtFf);}" fullword ascii
    $s7  = "function dOmcbJeqWYrNIJzRmDBwKtPt(zMpTvSbwvWXhfzqc,uTWZahDOIUphOenKjtrhXd,YoohVUGLaH){return String.fromCharCode(zMpTvSbwvWXhfzq" ascii
    $s8  = "function ld(HZsqodvLUdoNEwH){return String.fromCharCode(HZsqodvLUdoNEwH);}" fullword ascii
    $s9  = "function UoQHusubjzPeYJ(epAgbmERxnv,pxuaoctWr){return epAgbmERxnv.indexOf(pxuaoctWr);}" fullword ascii
    $s10 = "function dOmcbJeqWYrNIJzRmDBwKtPt(zMpTvSbwvWXhfzqc,uTWZahDOIUphOenKjtrhXd,YoohVUGLaH){return String.fromCharCode(zMpTvSbwvWXhfzq" ascii
    $s11 = "function PXNCtYfKNfnCXx(HdSydxVooiKkJ) {var LyToabPtQI = abMvrthtqtsPi.join(zDsxOQIkHaCAD[0]);var uTSnMVUNpNNgnLKOohGoMSOy, xrzK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}