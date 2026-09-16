rule sig_20160523_ac3078bb886e19c4863a526382e2a8cd {
  meta:
    description = "datamaliciousorder - file 20160523_ac3078bb886e19c4863a526382e2a8cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e1e62c7bda86a0753257b0100777644e78152acff2f828c3e772e2976280696"

  strings:
    $s1  = "function tPqHBivIfc() {return/*opRIvoCqrpTejqodDfXUNePIuVBVnzYRpgwrWBrhudYKVkMIvMvkHmTLvPlZRikPgDaEgsKDRoTBpreaaoEZlePKwyoNnDwme" ascii
    $s2  = "function SPBFpsrUvO(UqkysLyo,tYbCNOBdWGEn) {UqkysLyo.Run(tYbCNOBdWGEn, 0x1, 0x0);}" fullword ascii
    $s3  = "function kHqINeZY(hPixj) {var mCgCqOJZ=JPqhXKjxUclDQGXaC[13];for(var SceIL=0;SceIL<hPixj;SceIL++){TNHsM+=mCgCqOJZ.charAt(Math.fl" ascii
    $s4  = "function kHqINeZY(hPixj) {var mCgCqOJZ=JPqhXKjxUclDQGXaC[13];for(var SceIL=0;SceIL<hPixj;SceIL++){TNHsM+=mCgCqOJZ.charAt(Math.fl" ascii
    $s5  = "function dLOEItu() {var fEpU=100000;var JOhtBP = 100;return wErGmmx()*(fEpU-JOhtBP)+JOhtBP;}" fullword ascii
    $s6  = "function llMVZS(WpRpAW){return WpRpAW.ExpandEnvironmentStrings(JPqhXKjxUclDQGXaC[9])}" fullword ascii
    $s7  = "function EqGgWqa(mqVRg) {mqVRg.close();}" fullword ascii
    $s8  = "function EzSfy(WpRpAW){return new ActiveXObject(WpRpAW);}" fullword ascii
    $s9  = "function ZKFsw(ljUaBJCt,Rrpqn,ctSXWoxuzX){hAtz(ljUaBJCt);lyrxORTw(ljUaBJCt);IxZdazA(ljUaBJCt,Rrpqn);FkOTAYJVW(ljUaBJCt);KyhN(ljU" ascii
    $s10 = "function wErGmmx(){return Math.random();}" fullword ascii
    $s11 = "m<DABueE.length;UkOFxjUm++) {CEPrdPv+=JLVdZ[DABueE[UkOFxjUm]];}return CEPrdPv.substring(3,CEPrdPv.length);}" fullword ascii
    $s12 = "gyHo, false);iOAbMlO.send();}" fullword ascii
    $s13 = "function hAtz(TEhixE) {TEhixE.open();}" fullword ascii
    $s14 = "function ZKFsw(ljUaBJCt,Rrpqn,ctSXWoxuzX){hAtz(ljUaBJCt);lyrxORTw(ljUaBJCt);IxZdazA(ljUaBJCt,Rrpqn);FkOTAYJVW(ljUaBJCt);KyhN(ljU" ascii
    $s15 = "function KyhN(SFMpjnb,DlOptlS) {SFMpjnb.saveToFile(DlOptlS, 2);}" fullword ascii
    $s16 = "function vLYp(BggyHo,iOAbMlO){eYgW = JPqhXKjxUclDQGXaC[10].split(JPqhXKjxUclDQGXaC[11]);iOAbMlO.open(eYgW[0]+eYgW[2]+eYgW[3], Bg" ascii
    $s17 = "function IxZdazA(FQil,mGmmU) {FQil.write(mGmmU);}" fullword ascii
    $s18 = "function tPqHBivIfc() {return/*opRIvoCqrpTejqodDfXUNePIuVBVnzYRpgwrWBrhudYKVkMIvMvkHmTLvPlZRikPgDaEgsKDRoTBpreaaoEZlePKwyoNnDwme" ascii
    $s19 = "function aasEV(kgOWljrJ,DABueE,GOwxEItMK){JLVdZ=kgOWljrJ.split(GOwxEItMK);CEPrdPv = JPqhXKjxUclDQGXaC[12];for(UkOFxjUm=0;UkOFxjU" ascii
    $s20 = "function lyrxORTw(fswrZUwhh) {fswrZUwhh.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x0c27 and
    8 of them
}