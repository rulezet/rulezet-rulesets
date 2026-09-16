rule sig_20160524_c77ebd2f9f0e59ee0ab74d23d8d2b422 {
  meta:
    description = "datamaliciousorder - file 20160524_c77ebd2f9f0e59ee0ab74d23d8d2b422.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f87e7ec7297afd11d6e90f023f0fcb43f3436738b9be67127136625df1b1cff3"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "yuMGdtB[0]);}();var NvAFSdXnlaZF=function(){return new ActiveXObject(\"WScript.Shell\");}();var wzaVvKQSuIao = jVjfieRyuMGdtB[1]" ascii
    $s3  = "le(fCzmYZF, 2);}function jCwQpYd(XAOGs) {XAOGs.close();}function rfqTKBSRfh(zgACVctR,ryJFALUWGHYv) {zgACVctR.Run(ryJFALUWGHYv, 0" ascii
    $s4  = "Oi() + ypaZm[2];var qlyDMNXb=715-714;var WmmCUmexc = function(){return new ActiveXObject(JavzC(ypaZm[3],[0,2,4],ypaZm[4]));}();v" ascii
    $s5  = "ar fHWkCFq = bQtfdn(WmmCUmexc) + String.fromCharCode(92) + fHWkCFq;var AccOx = function(){return new ActiveXObject(JavzC(ypaZm[5" ascii
    $s6  = "BVthZueDKcaxatndMqwelrFMrwtNvdRsojDmqnKHqpQoILZtjAQGmivoHFrbNsLfwrhmZbKGpvYZKXdDbFDcFSEJqIKizAaMXsfedI*/WScript;}function Yfyrbd" ascii
    $s7  = "k=0;PGWvMsCk<mtVYhT.length;PGWvMsCk++) {aLcfFlo+=KpmpI[mtVYhT[PGWvMsCk]];}return aLcfFlo.substring(3,aLcfFlo.length);}function d" ascii
    $s8  = "x1, 0x0);}function QuAniOi() {var Bwhc=100000;var gfDuUi = 100;return rMqGdtg()*(Bwhc-gfDuUi)+gfDuUi;}function HUjczPRN(JPlMp) {" ascii
    $s9  = "false);xAbhhng.send();}function JavzC(aGOHdTYy,mtVYhT,WHSDTwZje){KpmpI=aGOHdTYy.split(WHSDTwZje);aLcfFlo = ypaZm[12];for(PGWvMsC" ascii
    $s10 = "eturn hrHEL;}function hwFeamFbEiSKRQ(fymoCiOiVgVCwl) {return new ActiveXObject(fymoCiOiVgVCwl);}');var AHKDdMKeRomrZHioprYN=[\"" ascii
    $s11 = "vtZ = [ypaZm[0], ypaZm[1]];var ohDY=185-185;while(true) {if(ohDY>TxvtZ.length) break;var ChYTCRrDw=TxvtZ[ohDY];var fHWkCFq=QuAni" ascii
    $s12 = "ction MXMkDrxz(FsWaRFUgL) {FsWaRFUgL.type=1;}function iDIlHHY(QgtU,ykxOI) {QgtU.write(ykxOI);}function vFuievgNtw() {return/*Hpz" ascii
    $s13 = "pZy(BgDUlo) {var DttFWBKygw=[];BgDUlo.position=DttFWBKygw.length*(3019639-776);}function vKhJ(lGxtsfZ,fCzmYZF) {lGxtsfZ.saveToFi" ascii
    $s14 = "ReJvmkvu = fwnkOe.OpenTextFile(gvDBcB,2,true);ReJvmkvu.Write('var ypaZm=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x" ascii
    $s15 = "],[0,2,4],ypaZm[6]));}();cdEg(ChYTCRrDw,AccOx);if (AccOx.status == 100+100) {var NiGZCSR = function() {return new ActiveXObject(" ascii
    $s16 = "6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function DQTpZGlOREFk() {var ReJvmkvu;var fwnkOe=function(){return new ActiveXObje" ascii
    $s17 = "CwQpYd(sAkwNiRE);}function cdEg(RlKoHa,xAbhhng){THAz = ypaZm[10].split(ypaZm[11]);xAbhhng.open(THAz[0]+THAz[2]+THAz[3], RlKoHa, " ascii
    $s18 = "yIuADfcBGlDL() {vFuievgNtw().Sleep(4397-230);}function rMqGdtg(){return Math.random();}function zRtj(lyIeDp) {lyIeDp.open();}fun" ascii
    $s19 = "ZGlOREFk();function (mOHrYKbxliFri) {return new ActiveXObject(mOHrYKbxliFri);}" fullword ascii
    $s20 = "kCFq);} catch(e) {}break;};ohDY++;}function bQtfdn(wZyRyC){return wZyRyC.ExpandEnvironmentStrings(ypaZm[9])}function RCerk(sAkwN" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}