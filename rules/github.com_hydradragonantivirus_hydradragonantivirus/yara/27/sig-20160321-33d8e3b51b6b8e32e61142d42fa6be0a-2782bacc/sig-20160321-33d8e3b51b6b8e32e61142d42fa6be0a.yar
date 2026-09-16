rule sig_20160321_33d8e3b51b6b8e32e61142d42fa6be0a {
  meta:
    description = "datamaliciousorder - file 20160321_33d8e3b51b6b8e32e61142d42fa6be0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c393c46baa0500c5e1b0759708c15698b19763f38ecbc2690a04bc65802bbe"

  strings:
    $s1  = "function ZrhJ(JLj){return JLj;};var Gb = \"162\";var fYckC = \"68\";var sX = \"2183\";var syqQG = \"4XwaL\";var QTGE = \"f\";var" ascii
    $s2  = "Vw;}()); x = H(); U = WScript[(function hJVBH(){return wznM;}()) + l(pxD) + zkpT](x); var pnqN = true; while (pnqN){try {U[ZF(oH" ascii
    $s3  = ")) + (function FTn(){return mWxm;}()) + (function Du(){return Qk0;}())]();WScript[(function Gsff(){return J0;}()) + (function QY" ascii
    $s4  = "(e){};}GnBh = WScript[UaY()](WvCX(UJjcn) + KWeU(JVmns) + nXq(ifsn) + (function h(){return yW;}()) + (function tJg(){return Zo;}(" ascii
    $s5  = " GdsO(syzj) + m1(mWxm) + (function YwGBL(){return Qk0;}())]();WScript[J0 + (function QDWp(){return JlhR;}())](t());var t0 = new " ascii
    $s6  = "xFPxQ){return dqmE - xFPxQ;};function UaY(){return u(wznM) + pxD + BAPcD(zkpT);};function t(){return 22;};function WHN(){var t0 " ascii
    $s7  = "e\";var iVaI = \"a\\x57\\x66H0\";var ct = \"IJ\\x51\";function kGIq(eDE){return eDE;};var BAvtK = \"%/\";var zWji = \"TEMP\";var" ascii
    $s8  = "true;break;}}function cDoA() {return Qk && Xul;};if (cDoA()){gNWBI = WsJW[(function Yee(){return yh;}()) + (function X(){return " ascii
    $s9  = "kbYNB;}()) + zkbky + ayo(JPg) + (function hjJ(){return tMq;}()) + eDRT(zD) + oLhAA + BcV(nhSes)]((function Coj(){return Jxb;}())" ascii
    $s10 = " xO(oVicd)] < 4 ) {WScript[(function QbPuK(){return J0;}()) + (function FUxf(){return JlhR;}())](t() * 10)};pnqN = false;} catch" ascii
    $s11 = " = \"hoNpVM\";var JlhR = COfwZ[\"c\\x68arAt\"](3);var J0 = \"S\\x6cee\";function p0(hUdz){return hUdz;};function o(F){return F;}" ascii
    $s12 = "Qn(Zd){return Zd;};var I = \"y\";var akg = I[\"c\\x68arAt\"](0);var P = \"\\x73\\x65\\x42od\";var CYO = \"e\\x73p\\x6fn\";var yC" ascii
    $s13 = " = \"\\x6fs\";var c0 = \"\\x66\\x6bja\";var pOU = LFt[\"c\\x68arAt\"](5);var FLAR = \"\\x61s\\x64\";function R(pHLk){return pHLk" ascii
    $s14 = "= \"wNF\";var svcwO = \"\\x72ite\";var lW = q[\"c\\x68arAt\"](0);function cvL(Y){return Y;};var fl = \"\\x70\\x65\";var qtu = \"" ascii
    $s15 = "64fas\\x64\";var eKw = \"s\";var C0 = syqQG[\"c\\x68arAt\"](3);function vLJ(qUpi){return qUpi;};function oGMN(q0){return q0;};fu" ascii
    $s16 = "\"dGo\";var cgP = \"se\";var g = pPlH[\"c\\x68arAt\"](2);var BPs = \"c\\x6c\";var DQP = \"oFile\";var EwOaw = \"S\\x61\\x76eT\";" ascii
    $s17 = "\";var qN = \"l\\x65\";var UB = mQw[\"c\\x68arAt\"](0);function k(E0){return E0;};function YOj(o0){return o0;};function xO(EB){r" ascii
    $s18 = " H0(wDK){return wDK;};var LFt = \"9Gagol0At4g\";var XQMWY = \"qh3nf\";var gapew = XQMWY[\"c\\x68arAt\"](4);var qa = \"sd\";var S" ascii
    $s19 = "rn MAY;}()) + (function IYhe(){return QTGE;}()) : (function bYEh(){return sX;}()) + ZrhJ(fYckC) + (function LFMB(){return Gb;}()" ascii
    $s20 = "ipt[(function s(){return wznM;}()) + PQdi(pxD) + PDKb(zkpT)](oxle + (function au(){return DS;}()) + RtE(lR) + Xf(Mf) + (function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}