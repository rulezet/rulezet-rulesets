rule sig_20160524_322ebd236e7c2c630324997e4c9a950f {
  meta:
    description = "datamaliciousorder - file 20160524_322ebd236e7c2c630324997e4c9a950f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cadd4855cb62abaee25ccb261c57cbb594b80acc84e0fcc2f7d1962ab6a4346b"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "NRQlam=function(){return new ActiveXObject(AhIPEK[0]);}();var yMWhDq=function(){return new ActiveXObject(\"WScript.Shell\");}();" ascii
    $s3  = "tC, 2);}function afRmVTe(aRpXS) {aRpXS.close();}function sdOlDvufdc(iWWkWLPE,bULvpwpweRHQ) {iWWkWLPE.Run(bULvpwpweRHQ, 0x1, 0x0)" ascii
    $s4  = "gPFgBdSyBQlWeJyRJMOdoEUWrpaoQASylnIrzkhlftAYavzWLuoXiVGsRcLaJvqnjfFVqKqsCqIuQAtvGvHlWFljliqgwK*/WScript;}function KVcdUefEP(edIJ" ascii
    $s5  = "Iv=VvhTl[axzw];var GPNKkuH=tBzXRGV() + rhYWxdrrKjyww[2];var qUKQuVDl=943-942;var AYqsMpQjK = function(){return new ActiveXObject" ascii
    $s6  = "function (ZQWNkxspkPIvDS) {return new ActiveXObject(ZQWNkxspkPIvDS);}" fullword ascii
    $s7  = "pen();ErsVkClF(SLNIUDCI);vkarSyg(SLNIUDCI,RhyWA);KVcdUefEP(SLNIUDCI);PQbB(SLNIUDCI,ugioQEGYsy);afRmVTe(SLNIUDCI);}function ZXyS(" ascii
    $s8  = "NU) {var UlxduHbCMI=[];edIJNU.position=UlxduHbCMI.length*(5583119-327);}function PQbB(GRSWScq,fqyaNtC) {GRSWScq.saveToFile(fqyaN" ascii
    $s9  = "tgEk = function(){return new ActiveXObject(JOpzQ(rhYWxdrrKjyww[5],[0,2,4],rhYWxdrrKjyww[6]));}();ZXyS(cvSwUwDIv,XtgEk);if (XtgEk" ascii
    $s10 = "TYkFjVJJbBaJ;vGVJqPSySKlU = NRQlam.OpenTextFile(kvuauXYMB,2,true);vGVJqPSySKlU.Write('var rhYWxdrrKjyww=[\"\\x68\\x74\\x74\\x70" ascii
    $s11 = "SSGK() {nbrqgAyiCm().Sleep(4474-114);}function SazrPIX(){return Math.random();}function pDIA(ZGfvlV) {ZGfvlV.open();}function Er" ascii
    $s12 = "eturn XBEpw;}function ZZuuAYvgnwbzqF(dApjTEovpNSZJw) {return new ActiveXObject(dApjTEovpNSZJw);}');var FlHBEloRyRfYfmJB=[\"\\x77" ascii
    $s13 = "3\\x68\\x70\\x64\\x46\\x56\\x4a\\x74\\x4a\\x42\\x7a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function JNeJVATR(" ascii
    $s14 = ";}function tBzXRGV() {var FRJb=100000;var gbvjZx = 100;return SazrPIX()*(FRJb-gbvjZx)+gbvjZx;}function bjiMmufY(pIQMU) {var qLgm" ascii
    $s15 = "end();}function JOpzQ(nroEzGnE,kyUUFN,hgxRzsVAU){ASiIK=nroEzGnE.split(hgxRzsVAU);eLZTBHM = rhYWxdrrKjyww[12];for(jNhRKiDn=0;jNhR" ascii
    $s16 = ".status == 100+100) {var jCWyicE = function() {return new ActiveXObject(JOpzQ(rhYWxdrrKjyww[7],[0,2,4],rhYWxdrrKjyww[8]));}();es" ascii
    $s17 = "ion oXynEA(JhuyXB){return JhuyXB.ExpandEnvironmentStrings(rhYWxdrrKjyww[9])}function esfZK(SLNIUDCI,RhyWA,ugioQEGYsy){SLNIUDCI.o" ascii
    $s18 = "KiDn<kyUUFN.length;jNhRKiDn++) {eLZTBHM+=ASiIK[kyUUFN[jNhRKiDn]];}return eLZTBHM.substring(3,eLZTBHM.length);}function HvcqvTbEs" ascii
    $s19 = "bEsSSGK();var VvhTl = [rhYWxdrrKjyww[0], rhYWxdrrKjyww[1]];var axzw=536-536;while(true) {if(axzw>VvhTl.length) break;var cvSwUwD" ascii
    $s20 = "zbisSD,TbovEzB){UORN = rhYWxdrrKjyww[10].split(rhYWxdrrKjyww[11]);TbovEzB.open(UORN[0]+UORN[2]+UORN[3], zbisSD, false);TbovEzB.s" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}