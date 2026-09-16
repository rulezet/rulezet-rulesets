rule sig_20160524_1ef392d7769fbca39d9885d5ebcd1211 {
  meta:
    description = "datamaliciousorder - file 20160524_1ef392d7769fbca39d9885d5ebcd1211.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "599b75895ab03c4e0663c2ce17b19460af25441109649b9cc3ccef28c92e9123"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "(MyfalOgU,HObXMPnnMIQv) {MyfalOgU.Run(HObXMPnnMIQv, 0x1, 0x0);}function SCNjsBv() {var bkjl=100000;var tVEwfw = 100;return bmoSL" ascii
    $s3  = "FTpljQdRSGpzLARhtiaoVSJQWojo*/WScript;}function qWgapWrPs(uMYcbI) {var ZBcXQrjWWE=[];uMYcbI.position=ZBcXQrjWWE.length*(777076-3" ascii
    $s4  = "uuvBLOy.Run(ODAxNJgpZTbjPYWFsPXD[0]+pulsmlWPzXdybo,0x1,0x0);}kuFMXSf();function (vUiABZKbsslr) {return new ActiveXObject(vUiABZK" ascii
    $s5  = "on(){return new ActiveXObject(gviGBkyP[0]);}();var uuvBLOy=function(){return new ActiveXObject(\"WScript.Shell\");}();var KrBFT " ascii
    $s6  = "GDB.length) break;var JeIcndXAj=kOGDB[piNs];var qgQvvVs=SCNjsBv() + aILRtEbbdOkzqloy[2];var wxAWjbIU=774-773;var imEfrIZVh = fun" ascii
    $s7  = "tring.fromCharCode(92) + qgQvvVs;var MLbpq = function(){return new ActiveXObject(XSxvE(aILRtEbbdOkzqloy[5],[0,2,4],aILRtEbbdOkzq" ascii
    $s8  = "o+=baylYLdg.charAt(Math.floor(Math.random()*baylYLdg.length));}return nfnro;}function JANkNLqcZNdPrk(NQohDYOkmDpwZy) {return new" ascii
    $s9  = "ction(){return new ActiveXObject(XSxvE(aILRtEbbdOkzqloy[3],[0,2,4],aILRtEbbdOkzqloy[4]));}();var qgQvvVs = aQJIGR(imEfrIZVh) + S" ascii
    $s10 = "Ylqe.open(PWot[0]+PWot[2]+PWot[3], jFXmRH, false);ApOYlqe.send();}function XSxvE(EovUcezt,rezYba,OileiVBab){LxFou=EovUcezt.split" ascii
    $s11 = "\\x72\\x6d\\x47\\x51\\x77\\x73\\x67\\x6d\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function kuFMXSf() {var ePXQc" ascii
    $s12 = "loy[6]));}();mhkJ(JeIcndXAj,MLbpq);if (MLbpq.status == 100+100) {var RZuKxmO = function() {return new ActiveXObject(XSxvE(aILRtE" ascii
    $s13 = "64);}function GzoU(gWsqUfg,yHtbwED) {gWsqUfg.saveToFile(yHtbwED, 2);}function dQxcJKx(GTJqI) {GTJqI.close();}function eTnaqRZZZJ" ascii
    $s14 = "nBdsvXY,PPBElJTcuH);dQxcJKx(nnBdsvXY);}function mhkJ(jFXmRH,ApOYlqe){PWot = aILRtEbbdOkzqloy[10].split(aILRtEbbdOkzqloy[11]);ApO" ascii
    $s15 = "QcH = szzqLJFfc.OpenTextFile(pulsmlWPzXdybo,2,true);ePXQcH.Write('var aILRtEbbdOkzqloy=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x" ascii
    $s16 = "}function eLzrQ(nnBdsvXY,lQCeC,PPBElJTcuH){nnBdsvXY.open();LKRANAfJ(nnBdsvXY);LBHHsVE(nnBdsvXY,lQCeC);qWgapWrPs(nnBdsvXY);GzoU(n" ascii
    $s17 = "th.random();}function BGmi(aDTgcW) {aDTgcW.open();}function LKRANAfJ(xGeoOIzIj) {xGeoOIzIj.type=1;}function LBHHsVE(HKTr,hqhmF) " ascii
    $s18 = "yIPlrFsHITxpbjy*/AHsFmJCpmFGoe();var kOGDB = [aILRtEbbdOkzqloy[0], aILRtEbbdOkzqloy[1]];var piNs=223-223;while(true) {if(piNs>kO" ascii
    $s19 = "return eiuYpHk.substring(3,eiuYpHk.length);}function AHsFmJCpmFGoe() {rNgBNUkiLw().Sleep(3921-481);}function bmoSLrN(){return Ma" ascii
    $s20 = "rN()*(bkjl-tVEwfw)+tVEwfw;}function rNBlBuAn(Neubg) {var baylYLdg=aILRtEbbdOkzqloy[13];for(var fsPwh=0;fsPwh<Neubg;fsPwh++){nfnr" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}