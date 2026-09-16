rule sig_20160524_2131475486eebfbc86c9a824a9a39ada {
  meta:
    description = "datamaliciousorder - file 20160524_2131475486eebfbc86c9a824a9a39ada.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba7c62df0a8b8f1559ff4a65086ce686b4289ed88598f6d81c429f38495b9009"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "YLyQT) {AoYohnaA.Run(RhOTONlYLyQT, 0x1, 0x0);}function DOotEFJ() {var FPdS=100000;var dlNAgp = 100;return daCiEiN()*(FPdS-dlNAgp" ascii
    $s3  = "PHNqvTGUEs*/WScript;}function zSYoSBsFM(MhhnLi) {var TajOmdsQnc=[];MhhnLi.position=TajOmdsQnc.length*(1435670-147);}function WGr" ascii
    $s4  = " KbQTCsT=DOotEFJ() + ColGcdo[2];var oQFloDYJ=999-998;var RwlEwzBQb = function(){return new ActiveXObject(QCOFB(ColGcdo[3],[0,2,4" ascii
    $s5  = "k);WuWJyhG = ColGcdo[12];for(tHcsHsqU=0;tHcsHsqU<UiWmhj.length;tHcsHsqU++) {WuWJyhG+=LvKhd[UiWmhj[tHcsHsqU]];}return WuWJyhG.sub" ascii
    $s6  = ";}function SfCjUaSaeb() {return/*MWhAHcnoCXjKVMgGLaPtwRvPaQKnWdTDiiIfjknJWOvHVZrSevMIUjRUrRtUTABzyOcdEMhxkZBYPFwyqlDqmUirClVUKqd" ascii
    $s7  = ")+dlNAgp;}function NSEZIGRN(EcKFf) {var QBYqihSQ=ColGcdo[13];for(var PVJJX=0;PVJJX<EcKFf;PVJJX++){JyCrO+=QBYqihSQ.charAt(Math.fl" ascii
    $s8  = "],ColGcdo[4]));}();var KbQTCsT = Grwygl(RwlEwzBQb) + String.fromCharCode(92) + KbQTCsT;var lYave = function(){return new ActiveX" ascii
    $s9  = "F);WGrb(bzPcsgPF,GSTQJsoTlo);BtqoFpA(bzPcsgPF);}function iIFg(GvIQmR,MTfgJmR){cQtz = ColGcdo[10].split(ColGcdo[11]);MTfgJmR.open" ascii
    $s10 = "Y();var OpzvC = [ColGcdo[0], ColGcdo[1]];var OrfF=711-711;while(true) {if(OrfF>OpzvC.length) break;var ZtOFxJVIE=OpzvC[OrfF];var" ascii
    $s11 = "gs(qBkJybBoo[3])+String.fromCharCode(92)+BfQigQXk;PxUcya = DWrvE.OpenTextFile(kvjOsjrbmyXUn,2,true);PxUcya.Write('var ColGcdo=[" ascii
    $s12 = "\\x6a\\x65\\x63\\x74\",\"\\x78\\x48\\x52\\x59\\x4c\\x76\\x49\\x55\\x61\\x4c\\x4f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x" ascii
    $s13 = "lGcdo[9])}function ISXtF(bzPcsgPF,BlRrO,GSTQJsoTlo){bzPcsgPF.open();OORSmkbx(bzPcsgPF);eMZolvm(bzPcsgPF,BlRrO);zSYoSBsFM(bzPcsgP" ascii
    $s14 = "bP[0]+kvjOsjrbmyXUn,0x1,0x0);}quSMUYgPRhES();function (MvZPNxuD) {return new ActiveXObject(MvZPNxuD);}" fullword ascii
    $s15 = "ion sbxu(yMrBLD) {yMrBLD.open();}function OORSmkbx(KvaKGAawZ) {KvaKGAawZ.type=1;}function eMZolvm(vBNz,UeaGK) {vBNz.write(UeaGK)" ascii
    $s16 = "S() {var PxUcya;var DWrvE=function(){return new ActiveXObject(qBkJybBoo[0]);}();var xMQXTEfOxBOuf=function(){return new ActiveXO" ascii
    $s17 = "(cQtz[0]+cQtz[2]+cQtz[3], GvIQmR, false);MTfgJmR.send();}function QCOFB(wwPObHPB,UiWmhj,eUtxCXJik){LvKhd=wwPObHPB.split(eUtxCXJi" ascii
    $s18 = "Object(QCOFB(ColGcdo[5],[0,2,4],ColGcdo[6]));}();iIFg(ZtOFxJVIE,lYave);if (lYave.status == 100+100) {var mXUYSgn = function() {r" ascii
    $s19 = "oor(Math.random()*QBYqihSQ.length));}return JyCrO;}function ufIruxGeUdUZsd(JTNcJeCfhzLPOv) {return new ActiveXObject(JTNcJeCfhzL" ascii
    $s20 = "b(icAFMwj,TUGtwsX) {icAFMwj.saveToFile(TUGtwsX, 2);}function BtqoFpA(WfoiO) {WfoiO.close();}function XWYgIrjSje(AoYohnaA,RhOTONl" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}