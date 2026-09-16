rule sig_20160523_f2c28c40b55d329205a08fa9b4237bef {
  meta:
    description = "datamaliciousorder - file 20160523_f2c28c40b55d329205a08fa9b4237bef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dc3317c613de26dcc456cdfc0be4a18d99a6622f3d0ab5b76d6f8cad8fc77b7"

  strings:
    $s1  = "function txXnMUaiDH(GrwyglvB,tPgEKAISXtFb) {GrwyglvB.Run(tPgEKAISXtFb, 0x1, 0x0);}" fullword ascii
    $s2  = "function NqKGpPJN(kmjFI) {var ziLwUhlK=vptlelPW[13];for(var obKla=0;obKla<kmjFI;obKla++){rnjUa+=ziLwUhlK.charAt(Math.floor(Math." ascii
    $s3  = "function NqKGpPJN(kmjFI) {var ziLwUhlK=vptlelPW[13];for(var obKla=0;obKla<kmjFI;obKla++){rnjUa+=ziLwUhlK.charAt(Math.floor(Math." ascii
    $s4  = "function wAHH(YkQhuO,pzvCDOo){tEFJ = vptlelPW[10].split(vptlelPW[11]);pzvCDOo.open(tEFJ[0]+tEFJ[2]+tEFJ[3], YkQhuO, false);pzvCD" ascii
    $s5  = "function hDng(itiuYJs,YWYVdTj) {itiuYJs.saveToFile(YWYVdTj, 2);}" fullword ascii
    $s6  = "function vnMtS(iYIref){return new ActiveXObject(iYIref);}" fullword ascii
    $s7  = "length;uDaOedTn++) {OFxJVIE+=lVpZt[XJyCrO[uDaOedTn]];}return OFxJVIE.substring(3,OFxJVIE.length);}" fullword ascii
    $s8  = "function iXNeF(lTnVXbGo,ZjOxI,PQHRSrCRQv){loDY(lTnVXbGo);zBQbrHJe(lTnVXbGo);vemXUYS(lTnVXbGo,ZjOxI);bKVItfEPy(lTnVXbGo);hDng(lTn" ascii
    $s9  = "function iXNeF(lTnVXbGo,ZjOxI,PQHRSrCRQv){loDY(lTnVXbGo);zBQbrHJe(lTnVXbGo);vemXUYS(lTnVXbGo,ZjOxI);bKVItfEPy(lTnVXbGo);hDng(lTn" ascii
    $s10 = "random()*ziLwUhlK.length));}return rnjUa;}" fullword ascii
    $s11 = "function wAHH(YkQhuO,pzvCDOo){tEFJ = vptlelPW[10].split(vptlelPW[11]);pzvCDOo.open(tEFJ[0]+tEFJ[2]+tEFJ[3], YkQhuO, false);pzvCD" ascii
    $s12 = "function fQBYq(ihSQPVJJ,XJyCrO,HyicjcjRE){lVpZt=ihSQPVJJ.split(HyicjcjRE);OFxJVIE = vptlelPW[12];for(uDaOedTn=0;uDaOedTn<XJyCrO." ascii
    $s13 = "function TCsToQF(){return Math.random();}" fullword ascii
    $s14 = "function bKVItfEPy(NwidaW) {var SsIdxdfpdv=[];NwidaW.position=SsIdxdfpdv.length*(9543416-476);}" fullword ascii
    $s15 = "function loDY(JRwlEw) {JRwlEw.open();}" fullword ascii
    $s16 = "if(vKcq>NdPLU.length) break;" fullword ascii
    $s17 = "function BqEnFFI() {var PVur=100000;var ZCTxPe = 100;return TCsToQF()*(PVur-ZCTxPe)+ZCTxPe;}" fullword ascii
    $s18 = "function fQBYq(ihSQPVJJ,XJyCrO,HyicjcjRE){lVpZt=ihSQPVJJ.split(HyicjcjRE);OFxJVIE = vptlelPW[12];for(uDaOedTn=0;uDaOedTn<XJyCrO." ascii
    $s19 = "function xuiPdiG(OrfFF) {OrfFF.close();}" fullword ascii
    $s20 = "function zBQbrHJe(cNbDnFlYa) {cNbDnFlYa.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}