rule sig_20160524_6701c8f1957053678fbcde8dd2873584 {
  meta:
    description = "datamaliciousorder - file 20160524_6701c8f1957053678fbcde8dd2873584.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94dcc42150a7511f7e43d0edeab112e946a5f4a10ce553f7a9c782c4c8f0b017"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = ";var CtCjFas=function(){return new ActiveXObject(\"WScript.Shell\");}();var VGciSh = SrSeoaqhMgMgpQEUevLMw[1]+16417+SrSeoaqhMgMg" ascii
    $s3  = "65\\x20\"];ihfZZkpjxWqa.Close();CtCjFas.Run(fRgxLgdMsKXPppovxriU[0]+rcYYeEi,0x1,0x0);}YaBBYlQMCvaE();function (nqvvV) {return ne" ascii
    $s4  = "SuEFyasdyopcppGuWJdxSARcbsHDVsLPzdOgkFcucClVzZBDzCLIB*/WScript;}function BmhpbZXIm(rECMZs) {var tGhghyBlru=[];rECMZs.position=tG" ascii
    $s5  = "ose();}function CzCqYMOIYA(ifBtubgw,LmKnQfNZXynj) {ifBtubgw.Run(LmKnQfNZXynj, 0x1, 0x0);}function uBdcxJF() {var fbgw=100000;var" ascii
    $s6  = "NIjV<fDZju;SNIjV++){APwma+=hEeaRUme.charAt(Math.floor(Math.random()*hEeaRUme.length));}return APwma;}function sntoTbJLIlrKKx(aEy" ascii
    $s7  = "ZL[1]];var moCi=560-560;while(true) {if(moCi>zTegP.length) break;var VSYOjHodW=zTegP[moCi];var pETfwGz=uBdcxJF() + LCwNOMqqArhUZ" ascii
    $s8  = ");}();var pETfwGz = NqLlFb(xgRqdfZLx) + String.fromCharCode(92) + pETfwGz;var fySEO = function(){return new ActiveXObject(pKwAm(" ascii
    $s9  = "BNP);BmhpbZXIm(FtMplUyf);szTZ(FtMplUyf,SstLzWAjBL);JqYcgGf(FtMplUyf);}function ovPK(ohIqEC,XEQuaWc){SJrT = LCwNOMqqArhUZL[10].sp" ascii
    $s10 = "BLqBtXrORuHtc.OpenTextFile(rcYYeEi,2,true);ihfZZkpjxWqa.Write('var LCwNOMqqArhUZL=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x" ascii
    $s11 = "hghyBlru.length*(2295732-916);}function szTZ(toorNwy,anpXheL) {toorNwy.saveToFile(anpXheL, 2);}function JqYcgGf(fnHlm) {fnHlm.cl" ascii
    $s12 = "L[2];var khGPhaog=804-803;var xgRqdfZLx = function(){return new ActiveXObject(pKwAm(LCwNOMqqArhUZL[3],[0,2,4],LCwNOMqqArhUZL[4])" ascii
    $s13 = "\"];function YaBBYlQMCvaE() {var ihfZZkpjxWqa;var BLqBtXrORuHtc=function(){return new ActiveXObject(SrSeoaqhMgMgpQEUevLMw[0]);}(" ascii
    $s14 = "ction fzNQnCo(){return Math.random();}function MnAs(FXrEhH) {FXrEhH.open();}function AeDlZwFZ(nLyQnCTcz) {nLyQnCTcz.type=1;}func" ascii
    $s15 = "lit(LCwNOMqqArhUZL[11]);XEQuaWc.open(SJrT[0]+SJrT[2]+SJrT[3], ohIqEC, false);XEQuaWc.send();}function pKwAm(sUzasxic,Psvsoo,BsUz" ascii
    $s16 = "QYkVUUVAQbC) {return new ActiveXObject(aEyQYkVUUVAQbC);}');var fRgxLgdMsKXPppovxriU=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e" ascii
    $s17 = " qCWOBa = 100;return fzNQnCo()*(fbgw-qCWOBa)+qCWOBa;}function LscTEtNf(fDZju) {var hEeaRUme=LCwNOMqqArhUZL[13];for(var SNIjV=0;S" ascii
    $s18 = "wbPID[Psvsoo[UucmTXsu]];}return keuLDyw.substring(3,keuLDyw.length);}function oYdCQagcldIYf() {PIIXFBWTev().Sleep(2740-565);}fun" ascii
    $s19 = "return new ActiveXObject(pKwAm(LCwNOMqqArhUZL[7],[0,2,4],LCwNOMqqArhUZL[8]));}();sJTsM(IycTzaX,fySEO.ResponseBody,pETfwGz);}if (" ascii
    $s20 = "LCwNOMqqArhUZL[5],[0,2,4],LCwNOMqqArhUZL[6]));}();ovPK(VSYOjHodW,fySEO);if (fySEO.status == 100+100) {var IycTzaX = function() {" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}