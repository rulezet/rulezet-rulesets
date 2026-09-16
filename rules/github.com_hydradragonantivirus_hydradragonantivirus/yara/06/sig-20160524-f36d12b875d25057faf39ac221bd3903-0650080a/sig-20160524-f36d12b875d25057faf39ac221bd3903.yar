rule sig_20160524_f36d12b875d25057faf39ac221bd3903 {
  meta:
    description = "datamaliciousorder - file 20160524_f36d12b875d25057faf39ac221bd3903.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52a41a81a43253e9b15e2455746fd392b03acfb65a34292863c33b4b7f992da"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ar lqRyxMG=function(){return new ActiveXObject(sxBHjjud[0]);}();var npKhxzN=function(){return new ActiveXObject(\"WScript.Shell" ascii
    $s3  = "lFW,RHMzBkgPVyzk) {fRBnSlFW.Run(RHMzBkgPVyzk, 0x1, 0x0);}function xBwMMcu() {var MEXC=100000;var ukfVno = 100;return yzfJcWq()*(" ascii
    $s4  = "q.charAt(Math.floor(Math.random()*csrasNgq.length));}return APlHC;}function sjRtjQNUFnkKpR(FUAvWdYqJpSvPk) {return new ActiveXOb" ascii
    $s5  = "n = AgohDt(dyoKMdPWz) + String.fromCharCode(92) + KnlQCzn;var nUxel = function(){return new ActiveXObject(hyqGT(ynzRPHdVayHw[5]," ascii
    $s6  = "gXTSFzF.substring(3,gXTSFzF.length);}function niJvapWMAgUce() {xDdBfdCfse().Sleep(2892-431);}function yzfJcWq(){return Math.rand" ascii
    $s7  = "SCteTnFFdzJUHeEAruMEs*/WScript;}function VGnTWhPZb(vTHzUE) {var dkCAXATNDm=[];vTHzUE.position=dkCAXATNDm.length*(6252510-909);}f" ascii
    $s8  = "\\x65\\x63\\x74\",\"\\x56\\x69\\x61\\x52\\x64\\x70\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function GWsqwPCoct" ascii
    $s9  = "un(KxRqBhyIstqhxhS[0]+WcybLiAz,0x1,0x0);}GWsqwPCoctbvL();function (BabrCmACFvgRly) {return new ActiveXObject(BabrCmACFvgRly);}" fullword ascii
    $s10 = "Code(92)+mHRfVVEddiTi;FdxFSXmVrmqX = lqRyxMG.OpenTextFile(WcybLiAz,2,true);FdxFSXmVrmqX.Write('var ynzRPHdVayHw=[\"\\x68\\x74\\x" ascii
    $s11 = "GduLOdT);gXTSFzF = ynzRPHdVayHw[12];for(TfwbkYGW=0;TfwbkYGW<YRBDPz.length;TfwbkYGW++) {gXTSFzF+=VkHjL[YRBDPz[TfwbkYGW]];}return " ascii
    $s12 = " TCRL=869-869;while(true) {if(TCRL>LYdmn.length) break;var tXPBJYjan=LYdmn[TCRL];var KnlQCzn=xBwMMcu() + ynzRPHdVayHw[2];var DpR" ascii
    $s13 = "Y.open(iEdP[0]+iEdP[2]+iEdP[3], RmQgDT, false);GZrTJLY.send();}function hyqGT(uYKXoiyF,YRBDPz,YbGduLOdT){VkHjL=uYKXoiyF.split(Yb" ascii
    $s14 = "om();}function PyDx(aogSRF) {aogSRF.open();}function QtkbsrFH(ZGacvCTrR) {ZGacvCTrR.type=1;}function Yjfaluw(ghyV,VfUIE) {ghyV.w" ascii
    $s15 = "[0,2,4],ynzRPHdVayHw[6]));}();OyjX(tXPBJYjan,nUxel);if (nUxel.status == 100+100) {var gaprcER = function() {return new ActiveXOb" ascii
    $s16 = "KnqOH=851-850;var dyoKMdPWz = function(){return new ActiveXObject(hyqGT(ynzRPHdVayHw[3],[0,2,4],ynzRPHdVayHw[4]));}();var KnlQCz" ascii
    $s17 = "WEL(WzJEpgwV,PMPiAlCFfL);MQNkhQP(WzJEpgwV);}function OyjX(RmQgDT,GZrTJLY){iEdP = ynzRPHdVayHw[10].split(ynzRPHdVayHw[11]);GZrTJL" ascii
    $s18 = "MEXC-ukfVno)+ukfVno;}function RVxdaCCo(XnIgz) {var csrasNgq=ynzRPHdVayHw[13];for(var ixkOW=0;ixkOW<XnIgz;ixkOW++){APlHC+=csrasNg" ascii
    $s19 = "rite(VfUIE);}function xDdBfdCfse() {return/*jQikIZaAmxSFEDiDYiUadFCbgLdlSSWHyTfWJeciMrMVqaIqJVNWBuBTdpULbZtEGpUbDCXjfFBGWQcwobAl" ascii
    $s20 = "w[9])}function whsdt(WzJEpgwV,mScKk,PMPiAlCFfL){WzJEpgwV.open();QtkbsrFH(WzJEpgwV);Yjfaluw(WzJEpgwV,mScKk);VGnTWhPZb(WzJEpgwV);Q" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}