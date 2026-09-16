rule sig_20160321_3e80aa39f56c5a2a5e9ac5553d88df3c {
  meta:
    description = "datamaliciousorder - file 20160321_3e80aa39f56c5a2a5e9ac5553d88df3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86900ad824d6147a993a4e2fae83f46d3f890a722826ec3ae221130f47984cb7"

  strings:
    $s1  = "function z1(gGke){return gGke;};var Z = \"vV5m8\";var b0 = \"\\x3162\";var Dx = Z[\"ch\\x61rAt\"](4);var ZFU = \"3\\x36\";var e2" ascii
    $s2  = "); Cn = WScript[(function W0(){return aG;}()) + (function y(){return AIW;}()) + nJFFD + h + i(nNs) + LX(p)](H0); var Ys = true; " ascii
    $s3  = "+ xqnZ(a) + Jy(eLu) + (function Rdj(){return b;}()) + (function lt(){return fAG;}())]();WScript[vss(xEVR)](BgAz());var ojO = new" ascii
    $s4  = "var AIW = \"reate\";var aG = \"C\";var UhDjd = function mGrm() {return WScript[aG + AIW + (function QDhqt(){return nJFFD;}()) + " ascii
    $s5  = "n zC(){return oRBm(kTcWV) + xvsB(ox) + Y + Ax + qV(YYeAj) + (function iaJ(){return p0;}());};function QV(FTR, ZWS){return FTR - " ascii
    $s6  = " (function HiNaR(){return fAG;}())]();WScript[i1(xEVR)](BgAz());var ojO = new this[gAo(rH)]();var vlmt = ojO[(function Ainob(){r" ascii
    $s7  = "+ i2] < 4 ) {WScript[(function jn(){return xEVR;}())](BgAz() * 10)};Ys = false;} catch(e){};}ANvD = WScript[C()](eXcF(sWfuq) + h" ascii
    $s8  = "\"i\";var h0 = \"Scr\";var z = liEOH[\"ch\\x61rAt\"](2);function E(rTX){return rTX;};function FeKLz(vT){return vT;};function A(Q" ascii
    $s9  = "aQ = \"n\\x64\";var U = \"se\\x63\\x6f\";var Gk = \"i\";var RK = \"ll\";var KOB = \"\\x4di\";var KLYD = \"get\";var ZS = \"Date" ascii
    $s10 = "on HuSJP(zfBmh){return zfBmh;};function xMyU(pxmUg){return pxmUg;};var tGgu = \"glyZdXih\";var fAG = \"s\";var b = tGgu[\"ch\\x6" ascii
    $s11 = "r X1 = \"EqfqKIH\";var TIBO = X1[\"ch\\x61rAt\"](2);var qOcso = \"dfas\\x64\";var y0 = \"\\x61s\";function n1(oFc){return oFc;};" ascii
    $s12 = "};function zvL(MISLY){return MISLY;};var aX = \"stDhiR\";var PX = \"D8jEsxP7Z\";var ehTH = PX[\"ch\\x61rAt\"](4);var wyPT = \"ri" ascii
    $s13 = "\";function VzG(FT){return FT;};var nJD = \"T3ne2\";var Bf = nJD[\"ch\\x61rAt\"](3);var LFoy = \"\\x54oF\\x69l\";var bNfHn = \"v" ascii
    $s14 = "hb = I[\"ch\\x61rAt\"](2);var Nf = \"\\x65b\\x62\";var SKmER = \"\\x25\\x2f\";var GViqm = \"%T\\x45\\x4d\\x50\";function Lb(eRNv" ascii
    $s15 = "r\";var KksLc = \"\\x74\";var M = \"ec\";var XD = \"\\x6a\";var Fk = \"Ob\";var xXzD = S[\"ch\\x61rAt\"](3);var a1 = \"Cr\\x65at" ascii
    $s16 = "function z1(gGke){return gGke;};var Z = \"vV5m8\";var b0 = \"\\x3162\";var Dx = Z[\"ch\\x61rAt\"](4);var ZFU = \"3\\x36\";var e2" ascii
    $s17 = "yo\";var WHLg = csA[\"ch\\x61rAt\"](4);var mGC = \"ar\\x61\";var LlazP = \"/\\x64iv\";var s0 = \":/\";var xHZG = \"tp\";var g = " ascii
    $s18 = "e0[\"ch\\x61rAt\"](5);var UVEk = \"t\\x79p\";var E1 = \"e\\x6e\";var znq = \"o\\x70\";function eXcF(tw){return tw;};var N0 = \"" ascii
    $s19 = "Xt);var Gy = \"H\";Gy = QV(vlmt, UzvI);return QV(jLgT, Gy);}var PvMe = false;var xLzyo = false;for (var DuAD = 0; DuAD < BgAz() " ascii
    $s20 = "while (Ys){try {Cn[(function nEzYO(){return Kl;}()) + X0](VW(MCcz) + (function vZ(){return Mbl;}()), zrR(g) + ltYC(xHZG) + s0 + " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}