rule sig_20160524_307807575ff8881d756ff96e4c2ca42b {
  meta:
    description = "datamaliciousorder - file 20160524_307807575ff8881d756ff96e4c2ca42b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0704a71e8b0923ed26b8f8beff1f938508af604ff3c751cade00460c2398c04"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "FLlEwUmEAHML*/WScript;}function dApjTEovp(NSZJwg) {var hTGJFkOGDB=[];NSZJwg.position=hTGJFkOGDB.length*(512437-431);}function SC" ascii
    $s3  = "ABPkwX) {Pwhnfnro.Run(ZjuNUpABPkwX, 0x1, 0x0);}function TeaRpXS() {var sdOl=100000;var Dvufdc = 100;return xoKXInX()*(sdOl-Dvufd" ascii
    $s4  = "harAt(Math.floor(Math.random()*wpweRHQn.length));}return yiCmG;}function uMYcbIZBcXQrjW(WEGzoUgWsqUfgy) {return new ActiveXObjec" ascii
    $s5  = "oEUWrp=TeaRpXS() + YggwpghzQUdFFoBkULM[2];var aoQASyln=424-423;var IrzkhlftA = function(){return new ActiveXObject(KPkWv(Yggwpgh" ascii
    $s6  = "\\x75\\x73\\x6e\\x61\\x64\\x78\\x57\\x75\\x58\\x71\\x5a\\x43\\x46\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];func" ascii
    $s7  = "zMF[2]+vzMF[3], TFOsLU, false);RThRlfZ.send();}function KPkWv(xGUpFUFD,hYIXuq,jHjWLuTnu){FoKHL=xGUpFUFD.split(jHjWLuTnu);ZEOYQbb" ascii
    $s8  = "An(BvVStTIV);}function oAXp(TFOsLU,RThRlfZ){vzMF = YggwpghzQUdFFoBkULM[10].split(YggwpghzQUdFFoBkULM[11]);RThRlfZ.open(vzMF[0]+v" ascii
    $s9  = "ction TNnJ(mrZmBy) {mrZmBy.open();}function IzIOaMhr(nTXMflBfO) {nTXMflBfO.type=1;}function FSZZuuA(Yvgn,wbzqF) {Yvgn.write(wbzq" ascii
    $s10 = "UdFFoBkULM[0], YggwpghzQUdFFoBkULM[1]];var OGct=862-862;while(true) {if(OGct>afRmV.length) break;var lWeJyRJMO=afRmV[OGct];var d" ascii
    $s11 = "IWLMEMz;var eAPcEOwGirQRS=function(){return new ActiveXObject(yULVctRnNaiOsMQmQCfegK[0]);}();var sIaudwqZ=function(){return new " ascii
    $s12 = ";if (VGsRc.status == 100+100) {var LaJvqnj = function() {return new ActiveXObject(KPkWv(YggwpghzQUdFFoBkULM[7],[0,2,4],YggwpghzQ" ascii
    $s13 = " = YggwpghzQUdFFoBkULM[12];for(vqnPvRva=0;vqnPvRva<hYIXuq.length;vqnPvRva++) {ZEOYQbb+=FoKHL[hYIXuq[vqnPvRva]];}return ZEOYQbb.s" ascii
    $s14 = "F);}function iZtTYncGJe() {return/*IcndXAjqgQvvVswxAWjbIUimEfrIZVhwehEeGhgNOMLbpqRZuKxmOlcSJLDyQDzhvEPyihXDqcUaDIgThRFPNVPSHLJGB" ascii
    $s15 = "enTextFile(kqielLl,2,true);JMgfvYIWLMEMz.Write('var YggwpghzQUdFFoBkULM=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x" ascii
    $s16 = "Rc = function(){return new ActiveXObject(KPkWv(YggwpghzQUdFFoBkULM[5],[0,2,4],YggwpghzQUdFFoBkULM[6]));}();oAXp(lWeJyRJMO,VGsRc)" ascii
    $s17 = "}break;};OGct++;}function pFtcSO(kGSoMc){return kGSoMc.ExpandEnvironmentStrings(YggwpghzQUdFFoBkULM[9])}function WFBgy(BvVStTIV," ascii
    $s18 = "c)+Dvufdc;}function iWWkWLPE(bULvp) {var wpweRHQn=YggwpghzQUdFFoBkULM[13];for(var brqgA=0;brqgA<bULvp;brqgA++){yiCmG+=wpweRHQn.c" ascii
    $s19 = "ubstring(3,ZEOYQbb.length);}function LXsKupiNsGNGY() {iZtTYncGJe().Sleep(3259-425);}function xoKXInX(){return Math.random();}fun" ascii
    $s20 = "L[0]+kqielLl,0x1,0x0);}yKswliuW();function (dGbvTgqZde) {return new ActiveXObject(dGbvTgqZde);}" fullword ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}