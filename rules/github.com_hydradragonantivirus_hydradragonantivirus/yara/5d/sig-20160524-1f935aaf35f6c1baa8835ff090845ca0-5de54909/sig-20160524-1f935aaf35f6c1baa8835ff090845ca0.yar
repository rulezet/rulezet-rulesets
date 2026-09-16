rule sig_20160524_1f935aaf35f6c1baa8835ff090845ca0 {
  meta:
    description = "datamaliciousorder - file 20160524_1f935aaf35f6c1baa8835ff090845ca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a17aab0a88b8855156d451681b003f00a1f30e1bd88f9e7f6385d5ad9e4100a6"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "JiVibHrHk=function(){return new ActiveXObject(\"WScript.Shell\");}();var skRZmLABSSzHr = KfQQtxrOlmZMsEBQCNiDfGm[1]+12878+KfQQtx" ascii
    $s3  = "\\x74\\x2e\\x65\\x78\\x65\\x20\"];snVQXSOvS.Close();RERhJiVibHrHk.Run(ifBhSaLEwSKNHKtzhPntDfl[0]+CiWmUyNj,0x1,0x0);}BcEDTQ();fun" ascii
    $s4  = "MoKXdXLtdsLUmEVrAkbcuroUREujpaEONlDaKrDMdUpprcYCyrqQYUDWNqvorIeIICpxkd*/WScript;}function lWumbwolf(JSWiaE) {var yvnwvEPTSV=[];J" ascii
    $s5  = "(UcucW) {UcucW.close();}function VKZpHFhwqr(rqAGWwrI,OLujkIOvcldd) {rqAGWwrI.Run(OLujkIOvcldd, 0x1, 0x0);}function fYUXbmE() {va" ascii
    $s6  = "r(var XkldN=0;XkldN<iGJEF;XkldN++){LGZmg+=yvdRYEve.charAt(Math.floor(Math.random()*yvdRYEve.length));}return LGZmg;}function Ldv" ascii
    $s7  = "uHCvu[3],[0,2,4],lkQjxCXuHCvu[4]));}();var WRXJNUp = TTvtoD(nyHdejlyo) + String.fromCharCode(92) + WRXJNUp;var IDPuG = function(" ascii
    $s8  = "];var WRXJNUp=fYUXbmE() + lkQjxCXuHCvu[2];var VmDKMdkH=659-658;var nyHdejlyo = function(){return new ActiveXObject(mOVzp(lkQjxCX" ascii
    $s9  = "XyST.type=1;}function LWRiJVJ(janq,Dxqmt) {janq.write(Dxqmt);}function JTssVFmZfS() {return/*RkfEKLnpYNuXjaSazLAwxFJKiTlOlnxhMXn" ascii
    $s10 = "SWiaE.position=yvnwvEPTSV.length*(2323532-998);}function wTve(CUirXWJ,tZvfxCs) {CUirXWJ.saveToFile(tZvfxCs, 2);}function ZmVjwYY" ascii
    $s11 = "PaB++) {WwHFcez+=XEaZy[qrGdjB[XQcRYPaB]];}return WwHFcez.substring(3,WwHFcez.length);}function oyWQMeqTVgqSz() {JTssVFmZfS().Sle" ascii
    $s12 = "\\x25\"];function BcEDTQ() {var snVQXSOvS;var auJZdHZ=function(){return new ActiveXObject(KfQQtxrOlmZMsEBQCNiDfGm[0]);}();var RE" ascii
    $s13 = "vGSjyVG) {return new ActiveXObject(vGSjyVG);}" fullword ascii
    $s14 = "ar BqYXt = [lkQjxCXuHCvu[0], lkQjxCXuHCvu[1]];var YXet=859-859;while(true) {if(YXet>BqYXt.length) break;var hPJdhACKx=BqYXt[YXet" ascii
    $s15 = "){return new ActiveXObject(mOVzp(lkQjxCXuHCvu[5],[0,2,4],lkQjxCXuHCvu[6]));}();MsnS(hPJdhACKx,IDPuG);if (IDPuG.status == 100+100" ascii
    $s16 = "= lkQjxCXuHCvu[10].split(lkQjxCXuHCvu[11]);SUHjrby.open(Fdkr[0]+Fdkr[2]+Fdkr[3], MiHkhq, false);SUHjrby.send();}function mOVzp(e" ascii
    $s17 = ") {var lnstlRc = function() {return new ActiveXObject(mOVzp(lkQjxCXuHCvu[7],[0,2,4],lkQjxCXuHCvu[8]));}();khQuF(lnstlRc,IDPuG.Re" ascii
    $s18 = "ep(2498-406);}function aIVYgnG(){return Math.random();}function vsTY(yHeJyx) {yHeJyx.open();}function YYoNiCmb(MGjmoXyST) {MGjmo" ascii
    $s19 = "eturn RJHwnV.ExpandEnvironmentStrings(lkQjxCXuHCvu[9])}function khQuF(aIVtRcgL,xVGsm,NAAZBsUeKo){aIVtRcgL.open();YYoNiCmb(aIVtRc" ascii
    $s20 = "LABSSzHr;snVQXSOvS = auJZdHZ.OpenTextFile(CiWmUyNj,2,true);snVQXSOvS.Write('var lkQjxCXuHCvu=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}