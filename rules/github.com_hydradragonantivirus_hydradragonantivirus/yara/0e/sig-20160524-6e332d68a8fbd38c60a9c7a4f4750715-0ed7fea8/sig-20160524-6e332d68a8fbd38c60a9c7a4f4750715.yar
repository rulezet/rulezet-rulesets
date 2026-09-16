rule sig_20160524_6e332d68a8fbd38c60a9c7a4f4750715 {
  meta:
    description = "datamaliciousorder - file 20160524_6e332d68a8fbd38c60a9c7a4f4750715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a85dc18b4e1f1029b1a560bf817dd76da3385734800ce91ba9bb48da6f768e30"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "SnlfUxuiutugymdXLOOglkrGDmfTSeWUJAiggIGBQqJFQIipLxudHSnViGeptYKiTFza*/WScript;}function RSLIqelRI(rkxyqa) {var YTmztvRafm=[];rkx" ascii
    $s3  = "kWah) {ekWah.close();}function CizQXZqxUA(LUqrwyLB,HcdJeXPVZbVQ) {LUqrwyLB.Run(HcdJeXPVZbVQ, 0x1, 0x0);}function hJBjaYY() {var " ascii
    $s4  = "5\\x78\\x65\\x20\"];pnDIunf.Close();yusBLBTNFm.Run(TozaSmcsidPtbaDMa[0]+OakmWcQeRTSVNd,0x1,0x0);}WcexJNdFN();function (wVyXAE) {" ascii
    $s5  = " jRJhe=0;jRJhe<UaDow;jRJhe++){gZuJS+=fHBANgak.charAt(Math.floor(Math.random()*fHBANgak.length));}return gZuJS;}function JDEEDNTj" ascii
    $s6  = " break;var URoxVWVPr=YMofn[zkMV];var fZqhWns=hJBjaYY() + zEmkpTPJZ[2];var OBUNmyIU=188-187;var YSMCXoSgH = function(){return new" ascii
    $s7  = "orJKGlodbumSWWAUqH[0]);}();var yusBLBTNFm=function(){return new ActiveXObject(\"WScript.Shell\");}();var dKflBSoCa = orJKGlodbum" ascii
    $s8  = "yqa.position=YTmztvRafm.length*(9699074-958);}function ruhU(wYYzsGC,GQIrucW) {wYYzsGC.saveToFile(GQIrucW, 2);}function quNPXKj(e" ascii
    $s9  = "x79\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function WcexJNdFN() {var pnDIunf;var noQCM=function(){return new " ascii
    $s10 = "EqLg=100000;var SAcnOF = 100;return DHqZyqB()*(EqLg-SAcnOF)+SAcnOF;}function CcLbpLCN(UaDow) {var fHBANgak=zEmkpTPJZ[13];for(var" ascii
    $s11 = "JEVbYH(wxVbIpyqqWgFFi) {return new ActiveXObject(wxVbIpyqqWgFFi);}');var TozaSmcsidPtbaDMa=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x7" ascii
    $s12 = "(OLKhybTk);vjpvoCn(OLKhybTk,yTpqC);RSLIqelRI(OLKhybTk);ruhU(OLKhybTk,HwCTgmAjKl);quNPXKj(OLKhybTk);}function pJlq(zfZakJ,UnZfmBZ" ascii
    $s13 = "(4947-215);}function DHqZyqB(){return Math.random();}function gTRz(HIiPoi) {HIiPoi.open();}function ODlkGslh(kozRyWMFT) {kozRyWM" ascii
    $s14 = "tatus == 100+100) {var zLpwpQP = function() {return new ActiveXObject(JlGRd(zEmkpTPJZ[7],[0,2,4],zEmkpTPJZ[8]));}();mjgQA(zLpwpQ" ascii
    $s15 = "ziwJllhpHpjiXmCUSu*/NNmOFhrXBZFAf();var YMofn = [zEmkpTPJZ[0], zEmkpTPJZ[1]];var zkMV=227-227;while(true) {if(zkMV>YMofn.length)" ascii
    $s16 = "){FUQN = zEmkpTPJZ[10].split(zEmkpTPJZ[11]);UnZfmBZ.open(FUQN[0]+FUQN[2]+FUQN[3], zfZakJ, false);UnZfmBZ.send();}function JlGRd(" ascii
    $s17 = "Q++) {OmxxpBR+=zIydz[IwmfYk[bJftZQaQ]];}return OmxxpBR.substring(3,OmxxpBR.length);}function NNmOFhrXBZFAf() {cHTyAFGyep().Sleep" ascii
    $s18 = "FT.type=1;}function vjpvoCn(BJcr,livTW) {BJcr.write(livTW);}function cHTyAFGyep() {return/*JVYBYuVIZafBJspzBAJtzeYBdivPjrLArKeCz" ascii
    $s19 = ";var hlKJM = function(){return new ActiveXObject(JlGRd(zEmkpTPJZ[5],[0,2,4],zEmkpTPJZ[6]));}();pJlq(URoxVWVPr,hlKJM);if (hlKJM.s" ascii
    $s20 = "(PmmHmd){return PmmHmd.ExpandEnvironmentStrings(zEmkpTPJZ[9])}function mjgQA(OLKhybTk,yTpqC,HwCTgmAjKl){OLKhybTk.open();ODlkGslh" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}