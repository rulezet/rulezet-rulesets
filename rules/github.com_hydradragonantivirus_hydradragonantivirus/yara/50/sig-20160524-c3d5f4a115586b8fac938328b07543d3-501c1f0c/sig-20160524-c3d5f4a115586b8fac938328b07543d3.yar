rule sig_20160524_c3d5f4a115586b8fac938328b07543d3 {
  meta:
    description = "datamaliciousorder - file 20160524_c3d5f4a115586b8fac938328b07543d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76c7a188e3a3fc81262ed6513bfa088beb4d9390e58755abec7dc949e8530da9"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = ".saveToFile(ryuSRQP, 2);}function BZVxtsA(JTcPs) {JTcPs.close();}function aHAOlnSRAx(DSqsRIGC,vGVfADfHRSLn) {DSqsRIGC.Run(vGVfAD" ascii
    $s3  = "var UIJowGE = aXxcEs(PWUouJSrn) + String.fromCharCode(92) + UIJowGE;var LzBPv = function(){return new ActiveXObject(NrQym(SFaicQ" ascii
    $s4  = "() + SFaicQ[2];var XHMayGnP=783-782;var PWUouJSrn = function(){return new ActiveXObject(NrQym(SFaicQ[3],[0,2,4],SFaicQ[4]));}();" ascii
    $s5  = "HpzgkF, false);HJocVQx.send();}function NrQym(JSmAYLdA,PgpMnp,NiWXPlWpo){ComkV=JSmAYLdA.split(NiWXPlWpo);zERPZmF = SFaicQ[12];fo" ascii
    $s6  = "r(VSdBKOzu=0;VSdBKOzu<PgpMnp.length;VSdBKOzu++) {zERPZmF+=ComkV[PgpMnp[VSdBKOzu]];}return zERPZmF.substring(3,zERPZmF.length);}f" ascii
    $s7  = "x4f\\x63\\x55\\x41\\x70\\x76\\x4a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function cXrlaLKYftm() {var RBxpGiqW" ascii
    $s8  = "ftm();function (exxaZerRh) {return new ActiveXObject(exxaZerRh);}" fullword ascii
    $s9  = "= [SFaicQ[0], SFaicQ[1]];var RdHn=652-652;while(true) {if(RdHn>aTgLt.length) break;var fVTEdvhYY=aTgLt[RdHn];var UIJowGE=iflbwUB" ascii
    $s10 = "unction eFGjrGNRDUmTS() {FqLBCpCCTH().Sleep(3961-739);}function tuLOyEH(){return Math.random();}function FMgm(GBBEaJ) {GBBEaJ.op" ascii
    $s11 = "[5],[0,2,4],SFaicQ[6]));}();yVFh(fVTEdvhYY,LzBPv);if (LzBPv.status == 100+100) {var bvitiPJ = function() {return new ActiveXObje" ascii
    $s12 = "fHRSLn, 0x1, 0x0);}function iflbwUB() {var qjCR=100000;var gsJTMx = 100;return tuLOyEH()*(qjCR-gsJTMx)+gsJTMx;}function uTcunBtK" ascii
    $s13 = "VX,2,true);RBxpGiqWNhtdiq.Write('var SFaicQ=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x61\\x72\\x6a\\x65\\x77\\x65\\x6c\\x6c" ascii
    $s14 = "=function(){return new ActiveXObject(VaNSWyHhjBcxSkSWqOAvV[0]);}();var XhquNFNfPjGZNL=function(){return new ActiveXObject(\"WScr" ascii
    $s15 = "MIp);BZVxtsA(JNzFhMnF);}function yVFh(HpzgkF,HJocVQx){rHYQ = SFaicQ[10].split(SFaicQ[11]);HJocVQx.open(rHYQ[0]+rHYQ[2]+rHYQ[3], " ascii
    $s16 = "en();}function LnACkurY(WDlptTssA) {WDlptTssA.type=1;}function UyzPMPD(lZbV,lNvsO) {lZbV.write(lNvsO);}function FqLBCpCCTH() {re" ascii
    $s17 = "on GHotJYzXA(dsamkL) {var AwcVVkSOjg=[];dsamkL.position=AwcVVkSOjg.length*(5911827-587);}function rIOq(KvKsItv,ryuSRQP) {KvKsItv" ascii
    $s18 = "ength));}return sLfRb;}function fseOfuKsTYSrSj(OCaFjsRsoDobPD) {return new ActiveXObject(OCaFjsRsoDobPD);}');var vdlQzXmw=[\"\\x" ascii
    $s19 = "n,UIJowGE);} catch(e) {}break;};RdHn++;}function aXxcEs(gWDAHs){return gWDAHs.ExpandEnvironmentStrings(SFaicQ[9])}function cFiCX" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}