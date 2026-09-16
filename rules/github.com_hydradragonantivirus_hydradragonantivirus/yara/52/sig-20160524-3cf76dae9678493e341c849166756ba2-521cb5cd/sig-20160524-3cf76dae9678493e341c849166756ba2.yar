rule sig_20160524_3cf76dae9678493e341c849166756ba2 {
  meta:
    description = "datamaliciousorder - file 20160524_3cf76dae9678493e341c849166756ba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf3053ba3e13f05a03967ab3d289b1860f56851d8a6286db21723b638837db8"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "nction(){return new ActiveXObject(dNxVUYp[0]);}();var yCYzdstH=function(){return new ActiveXObject(\"WScript.Shell\");}();var BJ" ascii
    $s3  = "OYBIcXBu*/WScript;}function NcJznTHPR(SwprXG) {var MgGqpaTgLt=[];SwprXG.position=MgGqpaTgLt.length*(2686588-174);}function iflb(" ascii
    $s4  = "QMz) {jPcsLfRb.Run(VLpgMnkaHQMz, 0x1, 0x0);}function GilugjU() {var fQgJ=100000;var mwrcTj = 100;return yOMgrtc()*(fQgJ-mwrcTj)+" ascii
    $s5  = "Lx=GilugjU() + kruolnaVPcntjhMOdFg[2];var KbVlsLEo=529-528;var qCmLOtQhy = function(){return new ActiveXObject(ZkFsr(kruolnaVPcn" ascii
    $s6  = "mwrcTj;}function IZFPxXCz(CVnYp) {var sSyBlWKE=kruolnaVPcntjhMOdFg[13];for(var ZDTqG=0;ZDTqG<CVnYp;ZDTqG++){tMeGw+=sSyBlWKE.char" ascii
    $s7  = "2]+oXTC[3], USEoaF, false);YsJEuzm.send();}function ZkFsr(qVqLVHNQ,spOTyQ,YFFJulGSJ){dNvdw=qVqLVHNQ.split(YFFJulGSJ);IAJohoG = k" ascii
    $s8  = "function GXGWfOfjfV() {return/*TEdvhYYUIJowGEXHMayGnPPWUouJSrnzSoRvfXedsLzBPvbvitiPJySobaDYySowKrxOXqeFWgFZSGZCyhLsXAOacfFGYMjNw" ascii
    $s9  = "ring(3,IAJohoG.length);}function VDRPkRdHnjpfW() {GXGWfOfjfV().Sleep(3583-439);}function yOMgrtc(){return Math.random();}functio" ascii
    $s10 = "n HOqp(KWSsot) {KWSsot.open();}function JDPjbOnY(FpgRGassQ) {FpgRGassQ.type=1;}function mwHuRrn(ehzr,faVwi) {ehzr.write(faVwi);}" ascii
    $s11 = "hMOdFg[0], kruolnaVPcntjhMOdFg[1]];var GJUC=671-671;while(true) {if(GJUC>qglLz.length) break;var htYvQVyUU=qglLz[GJUC];var ldtGh" ascii
    $s12 = "6f\\x56\\x7a\\x49\\x69\\x43\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function YBVtOuRIFzaJZb() {var AaCxVtEpR;v" ascii
    $s13 = "FmhiDhTM;AaCxVtEpR = jJMskQLrmdEcj.OpenTextFile(jMNmbxlaprqEOh,2,true);AaCxVtEpR.Write('var kruolnaVPcntjhMOdFg=[\"\\x68\\x74\\x" ascii
    $s14 = "(JIXuW.status == 100+100) {var yTKGFsm = function() {return new ActiveXObject(ZkFsr(kruolnaVPcntjhMOdFg[7],[0,2,4],kruolnaVPcntj" ascii
    $s15 = "ruolnaVPcntjhMOdFg[12];for(wRPVzezI=0;wRPVzezI<spOTyQ.length;wRPVzezI++) {IAJohoG+=dNvdw[spOTyQ[wRPVzezI]];}return IAJohoG.subst" ascii
    $s16 = " function(){return new ActiveXObject(ZkFsr(kruolnaVPcntjhMOdFg[5],[0,2,4],kruolnaVPcntjhMOdFg[6]));}();zvIB(htYvQVyUU,JIXuW);if " ascii
    $s17 = "ak;};GJUC++;}function nKnGAq(mHrQXp){return mHrQXp.ExpandEnvironmentStrings(kruolnaVPcntjhMOdFg[9])}function EJGaI(qeFBwQzD,AXUD" ascii
    $s18 = "eFBwQzD);}function zvIB(USEoaF,YsJEuzm){oXTC = kruolnaVPcntjhMOdFg[10].split(kruolnaVPcntjhMOdFg[11]);YsJEuzm.open(oXTC[0]+oXTC[" ascii
    $s19 = "wUBqjCR,gsJTMxu) {wUBqjCR.saveToFile(gsJTMxu, 2);}function TcunBtK(teDqs) {teDqs.close();}function mYKnlvRLNn(jPcsLfRb,VLpgMnkaH" ascii
    $s20 = "At(Math.floor(Math.random()*sSyBlWKE.length));}return tMeGw;}function dsamkLAwcVVkSO(jgrIOqKvKsItvr) {return new ActiveXObject(j" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}