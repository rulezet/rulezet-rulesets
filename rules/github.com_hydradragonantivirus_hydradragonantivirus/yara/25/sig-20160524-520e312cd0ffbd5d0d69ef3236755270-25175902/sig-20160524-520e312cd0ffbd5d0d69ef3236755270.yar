rule sig_20160524_520e312cd0ffbd5d0d69ef3236755270 {
  meta:
    description = "datamaliciousorder - file 20160524_520e312cd0ffbd5d0d69ef3236755270.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7edcb9dbcdfe9125c7323c01a6c1244e7c4c45230f93bf1c5cc237e6802ad5a2"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "on(){return new ActiveXObject(\"WScript.Shell\");}();var bCTmyIFcs = wnzsQWg[1]+16196+wnzsQWg[2];var QmoZuEXzE=NUKBWPhVKYNOS.Exp" ascii
    $s3  = "UNrwNyjCgyrQyRYeMkTJvGkxyKKMsCFvdMFOctWKocqAlRXdStDLHKuoCyggdLae*/WScript;}function iBLzanKIW(EbPsFW) {var LpVhQkFSUb=[];EbPsFW." ascii
    $s4  = ") {Gaxfr.close();}function tHXaRZFUky(JKSBmHGi,VwSQPquyxZDE) {JKSBmHGi.Run(VwSQPquyxZDE, 0x1, 0x0);}function KwQEqbe() {var fThc" ascii
    $s5  = "r(var dtlwX=0;dtlwX<Qklif;dtlwX++){XuVTD+=BYKnGgFk.charAt(Math.floor(Math.random()*BYKnGgFk.length));}return XuVTD;}function FHp" ascii
    $s6  = "e) {if(YlfU>VKUhw.length) break;var onvAXFlDV=VKUhw[YlfU];var XQwBMpp=KwQEqbe() + pJqJAGpaIiUOdqVgIz[2];var HZmVEhNy=869-868;var" ascii
    $s7  = "MlEQE(kiwJRAsPr) + String.fromCharCode(92) + XQwBMpp;var iYnbb = function(){return new ActiveXObject(Vgvkp(pJqJAGpaIiUOdqVgIz[5]" ascii
    $s8  = "ype=1;}function BlBZQzn(OoZy,hvPuW) {OoZy.write(hvPuW);}function YImhZeMEDx() {return/*VWqzgFpvjEhXxsWqOSnlAElUyAvcbdVUZnqiMCMdf" ascii
    $s9  = " {aNnjjNg+=htTnF[huZAmI[JwBxWrzu]];}return aNnjjNg.substring(3,aNnjjNg.length);}function geMzlHDlpZiES() {YImhZeMEDx().Sleep(414" ascii
    $s10 = "sJRFakjIIfD() {var pOIolzxpsgTYLs;var sTICisDxnvdfb=function(){return new ActiveXObject(wnzsQWg[0]);}();var NUKBWPhVKYNOS=functi" ascii
    $s11 = ",[0,2,4],pJqJAGpaIiUOdqVgIz[6]));}();jjSz(onvAXFlDV,iYnbb);if (iYnbb.status == 100+100) {var tShssfE = function() {return new Ac" ascii
    $s12 = "DovAspZdlcS(ewrXgJCOpjypkJ) {return new ActiveXObject(ewrXgJCOpjypkJ);}');var ChOjRXhhZQBYaBEySQuBG=[\"\\x77\\x73\\x63\\x72\\x69" ascii
    $s13 = "Cr);iBLzanKIW(iYYpsyNM);oPpn(iYYpsyNM,JoIQrjClQh);HhajtWZ(iYYpsyNM);}function jjSz(bNHddD,VmNKUSe){Mplz = pJqJAGpaIiUOdqVgIz[10]" ascii
    $s14 = "position=LpVhQkFSUb.length*(1178775-412);}function oPpn(akTTvOZ,rDMxFdP) {akTTvOZ.saveToFile(rDMxFdP, 2);}function HhajtWZ(Gaxfr" ascii
    $s15 = "=100000;var knOpEO = 100;return dDGUPCp()*(fThc-knOpEO)+knOpEO;}function sWzpTBGg(Qklif) {var BYKnGgFk=pJqJAGpaIiUOdqVgIz[13];fo" ascii
    $s16 = "dEnvironmentStrings(wnzsQWg[3])+String.fromCharCode(92)+bCTmyIFcs;pOIolzxpsgTYLs = sTICisDxnvdfb.OpenTextFile(QmoZuEXzE,2,true);" ascii
    $s17 = " kiwJRAsPr = function(){return new ActiveXObject(Vgvkp(pJqJAGpaIiUOdqVgIz[3],[0,2,4],pJqJAGpaIiUOdqVgIz[4]));}();var XQwBMpp = U" ascii
    $s18 = ".split(pJqJAGpaIiUOdqVgIz[11]);VmNKUSe.open(Mplz[0]+Mplz[2]+Mplz[3], bNHddD, false);VmNKUSe.send();}function Vgvkp(pgRlqESA,huZA" ascii
    $s19 = "QaQeXKDjJkQCKSbplzjbZxLRk*/geMzlHDlpZiES();var VKUhw = [pJqJAGpaIiUOdqVgIz[0], pJqJAGpaIiUOdqVgIz[1]];var YlfU=410-410;while(tru" ascii
    $s20 = "2\\x6a\\x65\\x63\\x74\",\"\\x65\\x62\\x71\\x77\\x79\\x48\\x73\\x6b\\x53\\x64\\x53\\x62\\x6e\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}