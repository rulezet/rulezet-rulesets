rule sig_20160523_82fed9251d48cc7225f8a97c79160df2 {
  meta:
    description = "datamaliciousorder - file 20160523_82fed9251d48cc7225f8a97c79160df2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58606dec4f074e90d578995de67bc73f0f2e5b30afdba379a13aa4f9e868c61e"

  strings:
    $s1  = "function qAhWlLMJtV(wdFfyyHA,lvJvVBvaSSun) {wdFfyyHA.Run(lvJvVBvaSSun, 0x1, 0x0);}" fullword ascii
    $s2  = "function qpSXkhjkZG() {return/*oqVtyBqNLrjMOboGxlggpSReWqTlrIGzvdgqgMyiosDHBqChOQJBgYafLqsPcnugvFZqymFYDcnJHxxhEyHTDKWqDgporjbMb" ascii
    $s3  = "function FmLGZNZZ(zgtlv) {var IGmKMRYD=NxYwIeOJJcWVpS[13];for(var nOUSC=0;nOUSC<zgtlv;nOUSC++){KhNyU+=IGmKMRYD.charAt(Math.floor" ascii
    $s4  = "function FmLGZNZZ(zgtlv) {var IGmKMRYD=NxYwIeOJJcWVpS[13];for(var nOUSC=0;nOUSC<zgtlv;nOUSC++){KhNyU+=IGmKMRYD.charAt(Math.floor" ascii
    $s5  = "riUXb.length;hejIUNrh++) {zlGoYGY+=KwpoQ[friUXb[hejIUNrh]];}return zlGoYGY.substring(3,zlGoYGY.length);}" fullword ascii
    $s6  = "function ehLC(rAZpru,sGZVdiS){JsQI = NxYwIeOJJcWVpS[10].split(NxYwIeOJJcWVpS[11]);sGZVdiS.open(JsQI[0]+JsQI[2]+JsQI[3], rAZpru, " ascii
    $s7  = "false);sGZVdiS.send();}" fullword ascii
    $s8  = "(Math.random()*IGmKMRYD.length));}return KhNyU;}" fullword ascii
    $s9  = "function VFXoa(ZqTNnumh,mulnf,SWIihnMypB){IXrY(ZqTNnumh);AnfayDdi(ZqTNnumh);yqbEHtT(ZqTNnumh,mulnf);ZXtTELpIs(ZqTNnumh);VNLg(ZqT" ascii
    $s10 = "function qpSXkhjkZG() {return/*oqVtyBqNLrjMOboGxlggpSReWqTlrIGzvdgqgMyiosDHBqChOQJBgYafLqsPcnugvFZqymFYDcnJHxxhEyHTDKWqDgporjbMb" ascii
    $s11 = "function taPry(LIInYfOd,friUXb,BZVdAILMH){KwpoQ=LIInYfOd.split(BZVdAILMH);zlGoYGY = NxYwIeOJJcWVpS[12];for(hejIUNrh=0;hejIUNrh<f" ascii
    $s12 = "function WToSxeq(){return Math.random();}" fullword ascii
    $s13 = "function RoGeapf() {var NPEq=100000;var SxkcHY = 100;return WToSxeq()*(NPEq-SxkcHY)+SxkcHY;}" fullword ascii
    $s14 = "function AnfayDdi(ZPTArAuTz) {ZPTArAuTz.type=1;}" fullword ascii
    $s15 = "function avoJs(tKFPxB){return new ActiveXObject(tKFPxB);}" fullword ascii
    $s16 = "function tGgyHHUjwBQbe() {qpSXkhjkZG().Sleep(2515591-120);}" fullword ascii
    $s17 = "function VNLg(YbpVhJn,XkmXYkW) {YbpVhJn.saveToFile(XkmXYkW, 2);}" fullword ascii
    $s18 = "function VFXoa(ZqTNnumh,mulnf,SWIihnMypB){IXrY(ZqTNnumh);AnfayDdi(ZqTNnumh);yqbEHtT(ZqTNnumh,mulnf);ZXtTELpIs(ZqTNnumh);VNLg(ZqT" ascii
    $s19 = "function IXrY(LaHjUI) {LaHjUI.open();}" fullword ascii
    $s20 = "function ZXtTELpIs(YsbNxY) {var lADjGGvYoS=[];YsbNxY.position=lADjGGvYoS.length*(911999-377);}" fullword ascii

  condition:
    uint16(0) == 0x1a27 and
    8 of them
}