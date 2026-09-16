rule sig_20160531_19d4266d422348cfb9207b38951ddf8f {
  meta:
    description = "datamaliciousorder - file 20160531_19d4266d422348cfb9207b38951ddf8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63152d3bdd21628fc099458def640ac7e521b0905b65b2372704635f7a7f79b3"

  strings:
    $s1  = "var HpEvPIaxlSShxp=function(){return WScript.CreateObject(QMnOmsfJcbDIrcbIXfhVIkGc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}()" ascii
    $s2  = "function rxrycomx(MiApnwBY,FGvMtYlpDWRQV) {var cUYMpF=[QMnOmsfJcbDIrcbIXfhVIkGc[15]];MiApnwBY[cUYMpF[0]]" fullword ascii
    $s3  = "function ECfBYYvIfN(rVTHYVM,BnGjTVGIr,hrzwTnPWm){WAUVUdMloMd=rVTHYVM.split(hrzwTnPWm);ASpgju = QMnOmsfJcbDIrcbIXfhVIkGc[0];for(g" ascii
    $s4  = "function pBrwdD(){return ECfBYYvIfN(QMnOmsfJcbDIrcbIXfhVIkGc[13],[0,3,6],QMnOmsfJcbDIrcbIXfhVIkGc[14]);}" fullword ascii
    $s5  = "function CCGKQsdIuU(){return ECfBYYvIfN(QMnOmsfJcbDIrcbIXfhVIkGc[11],[2,4,8,10],QMnOmsfJcbDIrcbIXfhVIkGc[12]);}" fullword ascii
    $s6  = "var qpfrsYX=function(){return new ActiveXObject(QMnOmsfJcbDIrcbIXfhVIkGc[1]);}();" fullword ascii
    $s7  = "function popPkHWSUJle(){return ECfBYYvIfN(QMnOmsfJcbDIrcbIXfhVIkGc[9],[1,5,7],QMnOmsfJcbDIrcbIXfhVIkGc[10]);}" fullword ascii
    $s8  = "function CDPkARQ(HaoRoUHBUIkEd) {var RgfKaiyIQJwHAYWRoSTt = keqUknmMKwjJXrPxatOBDofz.join(QMnOmsfJcbDIrcbIXfhVIkGc[7]);var izcjo" ascii
    $s9  = "function CDPkARQ(HaoRoUHBUIkEd) {var RgfKaiyIQJwHAYWRoSTt = keqUknmMKwjJXrPxatOBDofz.join(QMnOmsfJcbDIrcbIXfhVIkGc[7]);var izcjo" ascii
    $s10 = "function gELCUVNh(HNuqydzCpriyiYFJpl,iMbIUODgdtdeKzMHbQzu){return HNuqydzCpriyiYFJpl.charAt(iMbIUODgdtdeKzMHbQzu);}" fullword ascii
    $s11 = "function ECfBYYvIfN(rVTHYVM,BnGjTVGIr,hrzwTnPWm){WAUVUdMloMd=rVTHYVM.split(hrzwTnPWm);ASpgju = QMnOmsfJcbDIrcbIXfhVIkGc[0];for(g" ascii
    $s12 = "UIkEd.length);return GOnEHspaYdkplayqqnc;}" fullword ascii
    $s13 = "UmspUrumBUOp=0;gUmspUrumBUOp<BnGjTVGIr.length;gUmspUrumBUOp++) {ASpgju+=WAUVUdMloMd[BnGjTVGIr[gUmspUrumBUOp]];}return ASpgju.sub" ascii
    $s14 = "string(3,ASpgju.length);}" fullword ascii
    $s15 = "function axCnkwY(wOQISZuxzN,ZgsBG){return wOQISZuxzN.indexOf(ZgsBG);}" fullword ascii
    $s16 = "layqqnc += SpJqewXXKKspWewmssZa(izcjovGUAZmWnZJuF, NqbhAyvBScEiYs, XoZrMSSurMCcZUQyRwI);} while (OTsUSUJeMBpAHmgkGMcG < HaoRoUHB" ascii
    $s17 = "function qrYRgzL(){return HpEvPIaxlSShxp.ExpandEnvironmentStrings(popPkHWSUJle())}" fullword ascii
    $s18 = " (FxWUcZfJsjjFflKOmPZpMvUp == 64) GOnEHspaYdkplayqqnc += lsHkJLClsKlRyDbnPy(izcjovGUAZmWnZJuF, NqbhAyvBScEiYs);else GOnEHspaYdkp" ascii
    $s19 = "function br(IUKtLMqDYSepopoWRbxhpdfj){return String.fromCharCode(IUKtLMqDYSepopoWRbxhpdfj);}" fullword ascii
    $s20 = "function SpJqewXXKKspWewmssZa(pSBOUIUvmQVamd,cQsxBADgiQcgrOP,nBUexSrpmzwSRHImIvEKOl){return String.fromCharCode(pSBOUIUvmQVamd,c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}