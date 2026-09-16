rule sig_20160524_1719fe99c419a53f862b89dde407d536 {
  meta:
    description = "datamaliciousorder - file 20160524_1719fe99c419a53f862b89dde407d536.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87c917b60269bd85f9cc695cd7f40e4240c7861ad04ed830d5062190f7346a43"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "rn/*UwYtkgfSMSpmZLMsWpjDcLQKnBtfeSdGxoFESUmTnpIPgEelwsnyHJtuLiishVRiTAgjucmoIgUMhRqxPNkNgaQzdjRYeszejgAiQEfbW*/WScript;}function" ascii
    $s3  = "aveToFile(KzXqekm, 2);}function sfJNEsH(TyVqv) {TyVqv.close();}function YuuLDTgHlX(kBvLSleO,QcMloTqHYbqg) {kBvLSleO.Run(QcMloTqH" ascii
    $s4  = "c[PPBk];var UPTSqhH=mynEUgV() + NIweXGqWDFcBAvQ[2];var VuHWPmCE=683-682;var AwCYzcTUL = function(){return new ActiveXObject(eXfn" ascii
    $s5  = "xDM[3])+String.fromCharCode(92)+fqVgF;mvkmMjqFT = sbhKNIryquHue.OpenTextFile(XKmFTtBInu,2,true);mvkmMjqFT.Write('var NIweXGqWDFc" ascii
    $s6  = "GnYpX.length));}return IWeYk;}function QSMykNLVrlnNJp(CSlFrBvlPGmNKA) {return new ActiveXObject(CSlFrBvlPGmNKA);}');var oOaToSmi" ascii
    $s7  = "ury.status == 100+100) {var ZidqzvX = function() {return new ActiveXObject(eXfnX(NIweXGqWDFcBAvQ[7],[0,2,4],NIweXGqWDFcBAvQ[8]))" ascii
    $s8  = "\\x6e\\x6e\\x58\\x68\\x4e\\x52\\x4b\\x62\\x6f\\x62\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function jjekndDXSi" ascii
    $s9  = "ction qZdaxudcDbvyM() {gsJoxlTjix().Sleep(3230-974);}function IFLVHiB(){return Math.random();}function gPeY(AxSkoz) {AxSkoz.open" ascii
    $s10 = "ury = function(){return new ActiveXObject(eXfnX(NIweXGqWDFcBAvQ[5],[0,2,4],NIweXGqWDFcBAvQ[6]));}();ydPM(DhnaVBVoj,Ueury);if (Ue" ascii
    $s11 = "TEYxbuNk=0;TEYxbuNk<cBLEtd.length;TEYxbuNk++) {TGunmGb+=nOUUa[cBLEtd[TEYxbuNk]];}return TGunmGb.substring(3,TGunmGb.length);}fun" ascii
    $s12 = " fpXxcZcvN(yPSsYb) {var LwkezdtQgT=[];yPSsYb.position=LwkezdtQgT.length*(6240696-414);}function mEgW(YlvRqcz,KzXqekm) {YlvRqcz.s" ascii
    $s13 = "Ybqg, 0x1, 0x0);}function mynEUgV() {var NbIF=100000;var wDJbWb = 100;return IFLVHiB()*(NbIF-wDJbWb)+wDJbWb;}function nufsZwpc(Z" ascii
    $s14 = "bhKNIryquHue=function(){return new ActiveXObject(flxTWCZjLxDM[0]);}();var pLUJthfgZBHA=function(){return new ActiveXObject(\"WSc" ascii
    $s15 = ";}function DvKxbj(FEnFat){return FEnFat.ExpandEnvironmentStrings(NIweXGqWDFcBAvQ[9])}function VhlzJ(EKRlvCYe,sfuvG,kcOWlwnAXA){E" ascii
    $s16 = "ekndDXSiO();function (BVQnIvvqmaSFAp) {return new ActiveXObject(BVQnIvvqmaSFAp);}" fullword ascii
    $s17 = "se);DbUqLBX.send();}function eXfnX(jAVErMGY,cBLEtd,dtWeZQPQr){nOUUa=jAVErMGY.split(dtWeZQPQr);TGunmGb = NIweXGqWDFcBAvQ[12];for(" ascii
    $s18 = "();}function wNimpNtB(uQGLlZgIL) {uQGLlZgIL.type=1;}function UGJuFqG(jMWR,CtJiz) {jMWR.write(CtJiz);}function gsJoxlTjix() {retu" ascii
    $s19 = "ar QEFtc = [NIweXGqWDFcBAvQ[0], NIweXGqWDFcBAvQ[1]];var PPBk=212-212;while(true) {if(PPBk>QEFtc.length) break;var DhnaVBVoj=QEFt" ascii
    $s20 = ";}();VhlzJ(ZidqzvX,Ueury.ResponseBody,UPTSqhH);}if (VuHWPmCE > 0){try {YuuLDTgHlX(AwCYzcTUL,UPTSqhH);} catch(e) {}break;};PPBk++" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}