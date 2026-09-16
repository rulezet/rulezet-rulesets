rule sig_20160524_c5799d7eeae2d2916b5c3d60d22035bb {
  meta:
    description = "datamaliciousorder - file 20160524_c5799d7eeae2d2916b5c3d60d22035bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd067150eb458efa3c58a222b6a59c080b48f70cc41bdc4d2484d0caf6692bae"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "){return new ActiveXObject(MPlqFXorFtZQImgLNJdjn[0]);}();var KjellKVSCCi=function(){return new ActiveXObject(\"WScript.Shell\");" ascii
    $s3  = "YyhbfGwTvJRgIbRUczuMovZPEGE*/WScript;}function mDKhNYhDE(JLYOUp) {var qWrkcimoid=[];JLYOUp.position=qWrkcimoid.length*(8572310-9" ascii
    $s4  = "(YNEXrPMf,AyshKHvHGHtL) {YNEXrPMf.Run(AyshKHvHGHtL, 0x1, 0x0);}function WkmIcXg() {var JheB=100000;var KijicE = 100;return xKLDn" ascii
    $s5  = "i.Run(ahbclBhDZ[0]+wtcmUTlDJdqT,0x1,0x0);}rQmztfwD();function (COjoTZqQF) {return new ActiveXObject(COjoTZqQF);}" fullword ascii
    $s6  = "sSd+=VhlfZPkB.charAt(Math.floor(Math.random()*VhlfZPkB.length));}return JosSd;}function oLNXHmxNmOkxDx(lTDSluMevRaKBC) {return n" ascii
    $s7  = "yYwBxrco=LqMHP[DMsm];var UxzVVzF=WkmIcXg() + GdcSIvePufgtOjBKXj[2];var welMpBRM=240-239;var yPdXvbflg = function(){return new Ac" ascii
    $s8  = "e(92) + UxzVVzF;var nUMwj = function(){return new ActiveXObject(eMUVv(GdcSIvePufgtOjBKXj[5],[0,2,4],GdcSIvePufgtOjBKXj[6]));}();" ascii
    $s9  = "xjnu.write(PvMdk);}function zqkYbbtyxE() {return/*TQzsgfrjhWNvttVTOdDWSdVvCYKHqUfAivTrCGlXvgSMnaazbSuEkOmSNsmIhKHQsuhJRBYfDKRvaZ" ascii
    $s10 = "h.random();}function zMGI(enszEH) {enszEH.open();}function uhJllMFT(PTdVEHpjD) {PTdVEHpjD.type=1;}function HackXwr(xjnu,PvMdk) {" ascii
    $s11 = "d.open(ndMV[0]+ndMV[2]+ndMV[3], SWnsuR, false);goWsGmd.send();}function eMUVv(cBvbQyxT,FyuxBM,eLjZSgIwC){yvIgj=cBvbQyxT.split(eL" ascii
    $s12 = "bBr();var LqMHP = [GdcSIvePufgtOjBKXj[0], GdcSIvePufgtOjBKXj[1]];var DMsm=144-144;while(true) {if(DMsm>LqMHP.length) break;var l" ascii
    $s13 = "eturn efYVDry.substring(3,efYVDry.length);}function HKzHtQRgDJbBr() {zqkYbbtyxE().Sleep(4405-519);}function xKLDnlg(){return Mat" ascii
    $s14 = "lg()*(JheB-KijicE)+KijicE;}function smDujAFb(OhazL) {var VhlfZPkB=GdcSIvePufgtOjBKXj[13];for(var ftUdz=0;ftUdz<OhazL;ftUdz++){Jo" ascii
    $s15 = "39);}function pUgL(NSTLrCW,ilOlHiV) {NSTLrCW.saveToFile(ilOlHiV, 2);}function mnsOWFC(MONWG) {MONWG.close();}function MrlOqvIcwE" ascii
    $s16 = "FXorFtZQImgLNJdjn[3])+String.fromCharCode(92)+lDdVw;Rlmwr = ukEAEVgrdCrXh.OpenTextFile(wtcmUTlDJdqT,2,true);Rlmwr.Write('var Gdc" ascii
    $s17 = "1\\x6a\\x73\\x71\\x59\\x44\\x43\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function rQmztfwD() {var Rlmwr;var ukE" ascii
    $s18 = ",CyRtuQVJzs);mnsOWFC(iArAKJWy);}function lxiC(SWnsuR,goWsGmd){ndMV = GdcSIvePufgtOjBKXj[10].split(GdcSIvePufgtOjBKXj[11]);goWsGm" ascii
    $s19 = "lxiC(lyYwBxrco,nUMwj);if (nUMwj.status == 100+100) {var oFuTMxZ = function() {return new ActiveXObject(eMUVv(GdcSIvePufgtOjBKXj[" ascii
    $s20 = "zVVzF);} catch(e) {}break;};DMsm++;}function hdahxQ(mszOmS){return mszOmS.ExpandEnvironmentStrings(GdcSIvePufgtOjBKXj[9])}functi" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}