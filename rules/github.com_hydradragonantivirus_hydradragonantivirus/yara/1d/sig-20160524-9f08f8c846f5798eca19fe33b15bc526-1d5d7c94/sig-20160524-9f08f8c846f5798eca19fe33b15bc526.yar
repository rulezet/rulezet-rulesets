rule sig_20160524_9f08f8c846f5798eca19fe33b15bc526 {
  meta:
    description = "datamaliciousorder - file 20160524_9f08f8c846f5798eca19fe33b15bc526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "444387ca0c52733c03a8a8eb95be96b087942b0ce5bcbbce6a1c98671b1b883d"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "oUh.charAt(Math.floor(Math.random()*QoNTkoUh.length));}return awZzw;}function NDmvlQmBZkkcoE(eBOqudMldoTGEm) {return new ActiveX" ascii
    $s3  = "CeSMdUJafBoHAZlvHLFzpKbF*/WScript;}function jgQfdXkRs(ZlqTky) {var oZebWBEAbR=[];ZlqTky.position=oZebWBEAbR.length*(1510601-231)" ascii
    $s4  = "Object(eBOqudMldoTGEm);}');var lOSea=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];idfsycTInVQWI.Close();pn" ascii
    $s5  = "MZsYWs,GRtzDwPJIRwQ) {QmMZsYWs.Run(GRtzDwPJIRwQ, 0x1, 0x0);}function TfVeOQH() {var bxOD=100000;var lFrgLx = 100;return amPaMXM(" ascii
    $s6  = ";var bKBXFGo = UCrdtg(qQoxgBsPM) + String.fromCharCode(92) + bKBXFGo;var ZaPEv = function(){return new ActiveXObject(tqTVB(etvgh" ascii
    $s7  = "tXfqHR[1]];var kQxr=103-103;while(true) {if(kQxr>YAOvN.length) break;var TRpHAuVjg=YAOvN[kQxr];var bKBXFGo=TfVeOQH() + etvghtXfq" ascii
    $s8  = "uEpgc.open(lytM[0]+lytM[2]+lytM[3], tiKVXL, false);eLuEpgc.send();}function tqTVB(aGZmATsn,iegOPm,SCNPHNVLf){OsVUZ=aGZmATsn.spli" ascii
    $s9  = "on EKvqcTSLr() {var idfsycTInVQWI;var WokcS=function(){return new ActiveXObject(HssePvUi[0]);}();var pnARs=function(){return new" ascii
    $s10 = ";}function jZNN(RdRHbSz,rLVwiss) {RdRHbSz.saveToFile(rLVwiss, 2);}function VZXNFhW(nNzpu) {nNzpu.close();}function drApODBCFz(Qm" ascii
    $s11 = "vUi[3])+String.fromCharCode(92)+qlDWJ;idfsycTInVQWI = WokcS.OpenTextFile(QRAcnmpzc,2,true);idfsycTInVQWI.Write('var etvghtXfqHR=" ascii
    $s12 = "tXfqHR[5],[0,2,4],etvghtXfqHR[6]));}();QYEa(TRpHAuVjg,ZaPEv);if (ZaPEv.status == 100+100) {var ZjJfSxf = function() {return new " ascii
    $s13 = "dGx);jZNN(HbXRhdGx,rVVknyXGHN);VZXNFhW(HbXRhdGx);}function QYEa(tiKVXL,eLuEpgc){lytM = etvghtXfqHR[10].split(etvghtXfqHR[11]);eL" ascii
    $s14 = "htXfqHR[9])}function IKdgK(HbXRhdGx,Jqtsk,rVVknyXGHN){HbXRhdGx.open();WeeiGjcU(HbXRhdGx);kfkaXNa(HbXRhdGx,Jqtsk);jgQfdXkRs(HbXRh" ascii
    $s15 = "rn IbWmSRf.substring(3,IbWmSRf.length);}function TuDZjOSsDqXWU() {UIZlKZJMev().Sleep(3704-523);}function amPaMXM(){return Math.r" ascii
    $s16 = "d.write(ErcYW);}function UIZlKZJMev() {return/*mLzbSaUwoWNLLrdyTFnPaBspPyOcypAHNqbjSuonATNXWEwURTMhwFJpxfLyglQmhpwKMiCxGjHEbkIJI" ascii
    $s17 = ")*(bxOD-lFrgLx)+lFrgLx;}function qqgLdFCH(vXDVM) {var QoNTkoUh=etvghtXfqHR[13];for(var BICuP=0;BICuP<vXDVM;BICuP++){awZzw+=QoNTk" ascii
    $s18 = "0]+QRAcnmpzc,0x1,0x0);}EKvqcTSLr();function (tfxmpwO) {return new ActiveXObject(tfxmpwO);}" fullword ascii
    $s19 = "andom();}function PSDY(jAqpfm) {jAqpfm.open();}function WeeiGjcU(fVyzEhrCQ) {fVyzEhrCQ.type=1;}function kfkaXNa(SLMd,ErcYW) {SLM" ascii
    $s20 = "HR[2];var KwgCDujU=320-319;var qQoxgBsPM = function(){return new ActiveXObject(tqTVB(etvghtXfqHR[3],[0,2,4],etvghtXfqHR[4]));}()" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}