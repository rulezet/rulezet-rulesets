rule sig_20160524_3fc819b314c6abf1683e52f85c7ac206 {
  meta:
    description = "datamaliciousorder - file 20160524_3fc819b314c6abf1683e52f85c7ac206.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b275244d75362e0c7e24a4b1c2cc79bd6283958df67db0cce5c1065bc70a0436"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "yD[0]);}();var SCsFNuS=function(){return new ActiveXObject(\"WScript.Shell\");}();var ONMnRmhy = okrIIVehbccyD[1]+16451+okrIIVeh" ascii
    $s3  = "H.Run(OgqChYomGRTC, 0x1, 0x0);}function AXAydPM() {var AQCe=100000;var XADbUq = 100;return jRYesze()*(AQCe-XADbUq)+XADbUq;}funct" ascii
    $s4  = "Cg[4]));}();var xbuNknO = sHTyVq(GbyZiIFLV) + String.fromCharCode(92) + xbuNknO;var kozwN = function(){return new ActiveXObject(" ascii
    $s5  = "1-141;while(true) {if(qczK>OWlwn.length) break;var eZQPQrTEY=OWlwn[qczK];var xbuNknO=AXAydPM() + nRdSoNSsxsGjkaacDADdCg[2];var U" ascii
    $s6  = "ADdCg[12];for(gjucmoIg=0;gjucmoIg<yHJtuL.length;gjucmoIg++) {xPNkNga+=UMhRq[yHJtuL[gjucmoIg]];}return xPNkNga.substring(3,xPNkNg" ascii
    $s7  = "UaTGunm=660-659;var GbyZiIFLV = function(){return new ActiveXObject(mTnpI(nRdSoNSsxsGjkaacDADdCg[3],[0,2,4],nRdSoNSsxsGjkaacDADd" ascii
    $s8  = ") {QEfbWq.open();}function ZdaxudcD(bvyMgWnDt) {bvyMgWnDt.type=1;}function ZVibuse(OAfy,SjeUZ) {OAfy.write(SjeUZ);}function hoQP" ascii
    $s9  = "Po) {fSRQvQl.saveToFile(vhnqSPo, 2);}function tYqyffj(ULgsj) {ULgsj.close();}function WrpvZEZiDn(VDWiajOH,OgqChYomGRTC) {VDWiajO" ascii
    $s10 = "yVq(msfJNE){return msfJNE.ExpandEnvironmentStrings(nRdSoNSsxsGjkaacDADdCg[9])}function HlXkB(vLSleOQc,MloTq,HYbqggsJox){vLSleOQc" ascii
    $s11 = "(WqZueW,2,true);aFTuQ.Write('var nRdSoNSsxsGjkaacDADdCg=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61\\x6d\\x65\\x72\\x69\\x63\\x6" ascii
    $s12 = "impNtBu = function() {return new ActiveXObject(mTnpI(nRdSoNSsxsGjkaacDADdCg[7],[0,2,4],nRdSoNSsxsGjkaacDADdCg[8]));}();HlXkB(imp" ascii
    $s13 = ".open();ZdaxudcD(vLSleOQc);ZVibuse(vLSleOQc,MloTq);MOxtciLMx(vLSleOQc);nNzK(vLSleOQc,HYbqggsJox);tYqyffj(vLSleOQc);}function lTj" ascii
    $s14 = "ript;}function MOxtciLMx(KQqOsq) {var PsFrwdvxVm=[];KQqOsq.position=PsFrwdvxVm.length*(3942994-705);}function nNzK(fSRQvQl,vhnqS" ascii
    $s15 = "a.length);}function BvlPGmNKAhqmZ() {hoQPkwsSOT().Sleep(4631-804);}function jRYesze(){return Math.random();}function jgAi(QEfbWq" ascii
    $s16 = "tk, false);gfSMSpm.send();}function mTnpI(PgEelwsn,yHJtuL,iishVRiTA){UMhRq=PgEelwsn.split(iishVRiTA);xPNkNga = nRdSoNSsxsGjkaacD" ascii
    $s17 = "oor(Math.random()*DgSQaAhK.length));}return EpReX;}function uSmADapbzanfsK(erUunRqYMjsMay) {return new ActiveXObject(erUunRqYMjs" ascii
    $s18 = "\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function FLrGcbPiwIuCaP() {var aFTuQ;var BcFIG=function(){return new ActiveXObject(o" ascii
    $s19 = "QMsAS[0]+WqZueW,0x1,0x0);}FLrGcbPiwIuCaP();function (RVnrjB) {return new ActiveXObject(RVnrjB);}" fullword ascii
    $s20 = "NtBu,kozwN.ResponseBody,xbuNknO);}if (UUaTGunm > 0){try {WrpvZEZiDn(GbyZiIFLV,xbuNknO);} catch(e) {}break;};qczK++;}function sHT" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}