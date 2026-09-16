rule sig_20160524_356d3db405ad79bbda71fd0f51b20d85 {
  meta:
    description = "datamaliciousorder - file 20160524_356d3db405ad79bbda71fd0f51b20d85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acbba4972fd191c462793ffb6290f46b5484b3ea5a95e29930933f749d13517d"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "unction(){return new ActiveXObject(RfMNGPE[0]);}();var xmyVOdXRyta=function(){return new ActiveXObject(\"WScript.Shell\");}();va" ascii
    $s3  = "\\x20\"];cUXcQEqfqpr.Close();xmyVOdXRyta.Run(MUvKaqWZFPWUJbhjfgIPeTD[0]+ovYOmyfJT,0x1,0x0);}bhLvJhq();function (LdEJzAQcUq) {ret" ascii
    $s4  = "I.close();}function AtqTVBaGZm(ATsniegO,PmSCNPHNVLfh) {ATsniegO.Run(PmSCNPHNVLfh, 0x1, 0x0);}function LsTtDfs() {var zUEI=100000" ascii
    $s5  = "kaXNaSLMdErcYWjgQfdXkRsZlqTkyoZebWBEAbRjZNNRdRHbSzrLVwiss*/WScript;}function tskrVVkny(XGHNQY) {var EatiKVXLeL=[];XGHNQY.positio" ascii
    $s6  = "KGAug;esPcx++){zFXmm+=OEbfqTpR.charAt(Math.floor(Math.random()*OEbfqTpR.length));}return zFXmm;}function BFLGpktBJCoHqu(NumWJOfU" ascii
    $s7  = "hile(true) {if(CHvX>yMGTJ.length) break;var wvkeetFrR=yMGTJ[CHvX];var OjXlrpu=LsTtDfs() + ohYhp[2];var tpOITsXk=768-767;var QNJa" ascii
    $s8  = "QjqAV = function(){return new ActiveXObject(GqVqf(ohYhp[3],[0,2,4],ohYhp[4]));}();var OjXlrpu = BICuPa(QNJaQjqAV) + String.fromC" ascii
    $s9  = "harCode(92) + OjXlrpu;var BznjE = function(){return new ActiveXObject(GqVqf(ohYhp[5],[0,2,4],ohYhp[6]));}();XFGo(wvkeetFrR,BznjE" ascii
    $s10 = "tmXzIO) {return new ActiveXObject(NumWJOfUtmXzIO);}');var MUvKaqWZFPWUJbhjfgIPeTD=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x" ascii
    $s11 = "n=EatiKVXLeL.length*(8644749-191);}function uEpg(clytMFi,hRkzKjZ) {clytMFi.saveToFile(hRkzKjZ, 2);}function cLfwWxx(ALEEI) {ALEE" ascii
    $s12 = "d(LgCiefjz);xIKdgKH(LgCiefjz,arSTR);tskrVVkny(LgCiefjz);uEpg(LgCiefjz,pHAuVjgbKB);cLfwWxx(LgCiefjz);}function XFGo(KwgCDu,jUqQox" ascii
    $s13 = "FB+=hZJbQ[dzOHil[baTVMltl]];}return dhQUIFB.substring(3,dhQUIFB.length);}function VZXNFhWnNzpud() {EzqVGdTOsV().Sleep(5152-218);" ascii
    $s14 = ";cUXcQEqfqpr = WlhSlePBVuN.OpenTextFile(ovYOmyfJT,2,true);cUXcQEqfqpr.Write('var ohYhp=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x" ascii
    $s15 = ";var AObIuR = 100;return HcNrgQk()*(zUEI-AObIuR)+AObIuR;}function gIHhfCjp(KGAug) {var OEbfqTpR=ohYhp[13];for(var esPcx=0;esPcx<" ascii
    $s16 = "g){BsPM = ohYhp[10].split(ohYhp[11]);jUqQoxg.open(BsPM[0]+BsPM[2]+BsPM[3], KwgCDu, false);jUqQoxg.send();}function GqVqf(Gvngyrw" ascii
    $s17 = ");if (BznjE.status == 100+100) {var dkXlMaj = function() {return new ActiveXObject(GqVqf(ohYhp[7],[0,2,4],ohYhp[8]));}();odwsi(d" ascii
    $s18 = "}function HcNrgQk(){return Math.random();}function Qxrc(IElYla) {IElYla.open();}function BmrJUCrd(tgehFJVsG) {tgehFJVsG.type=1;}" ascii
    $s19 = "function xIKdgKH(bXRh,dGxJq) {bXRh.write(dGxJq);}function EzqVGdTOsV() {return/*UZIbWmSRfNOsamPaMXMPSDYjAqpfmWeeiGjcUfVyzEhrCQkf" ascii
    $s20 = "58\\x56\\x56\\x45\\x50\\x58\\x5a\\x6e\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function bhLvJhq() {var cUXcQEqf" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}