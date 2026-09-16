rule sig_20160321_efb599060000e876ec284c1bc940c6ce {
  meta:
    description = "datamaliciousorder - file 20160321_efb599060000e876ec284c1bc940c6ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f0a7c9c93555245afcd1c6959ff38973fdd44439ebe4272655f7fdaa8ef263d"

  strings:
    $s1  = "function c(Q0){return Q0;};var x0 = \"\\x381\\x36\\x32\";var SHJS = \"\\x3218\\x33\\x36\";function SpD(Ip){return Ip;};var Jr = " ascii
    $s2  = " = function K() {return WScript[ONQRr + NOGBJ(Jn) + iRRG + mho(tL)]((function LOIaA(){return YMcIu;}()) + (function JbED(){retur" ascii
    $s3  = "function xlYSb(){return FIUE;}()) + (function taC(){return vJLn;}()) + oC + irM]();WScript[ZhMTb(qT) + (function W(){return D;}(" ascii
    $s4  = "on Dl0(){return Dpi;}()) + (function PFWD(){return sGS;}()) + nJP + p2] < 4 ) {WScript[amG(qT) + xPlNz(D)](Mb() * 10)};jJ = fals" ascii
    $s5  = "]();var X = Eh[BHy(Eq) + (function tTa(){return FIUE;}()) + fVvYe(vJLn) + oC + yI(irM)]();WScript[qT + D](Mb());var Eh = new thi" ascii
    $s6  = "o + (function J(){return Wrsp;}()) + (function ACL(){return kx;}()); gVfE = rAxw(); Ar = WScript[ONQRr + (function MW(){return J" ascii
    $s7  = "on hVf(){return loGr;}())](i, 2 );gP[(function WAujA(){return yyZwU;}()) + Ynpra(lele)]();M(i);QLJB = \"\" + ix(JuC) + aPyzA + (" ascii
    $s8  = " + hnis(Go) + Qwjz(eg);};function rOp(AL, Z){return AL - Z;};function tcr(){return EAzmm(ONQRr) + ZbZhR(Jn) + (function zU(){ret" ascii
    $s9  = "n rxW() {return K0 && FnKKv;};if (rxW()){i = HNKZk[(function GjZSM(){return mUIF;}()) + ALZj + (function PzFN(){return WKvg;}())" ascii
    $s10 = "e;} catch(e){};}gP = WScript[tcr()](Zmh(KlR) + QQOPh(YjHjd) + (function hpaNg(){return iXVMg;}()));gP[((function pqCSA(){return " ascii
    $s11 = "JuC = \"\\x61sdl\";function Ynpra(rUGcG){return rUGcG;};var lele = \"\\x6c\\x6fse\";var yyZwU = \"c\";var loGr = \"File\";var Xn" ascii
    $s12 = "(amHyL)](ns(C0), CNPyU + (function SgaJq(){return R;}()) + (function La(){return p1;}()) + JFx(SSZIV) + EP(hLSwK) + (function Eg" ascii
    $s13 = " u(){return oC;}()) + irM]();var QLJB = \"gUXE\";QLJB = rOp(juU, X);var TeYRI = \"U\";TeYRI = rOp(dvQq, juU);return rOp(QLJB, Te" ascii
    $s14 = "{HNKZk[(function mppx(){return A;}())](zrcr, 0, 0);};function rAxw(){return OXn + (function hSV(){return SMeoe;}()) + Q + AdO(x)" ascii
    $s15 = "x(){return fzL;}()) + fF + (function t(){return BF;}()) + (function OA(){return oleTI;}()) + qdYDE(RtNP) + (function VYTOD(){ret" ascii
    $s16 = "nction N0(){return HHy;}()) + rSeYJ(uy) + ZUtV + pW(Awk) + HVEs(O) + mS(QK) + oC0(CerU) + NoWE + BfMem(rb) + (function fjGMa(){r" ascii
    $s17 = " + ML(fdiej) + Dx + bRWTB(tq) + (function Qy(){return DQ;}())](aMqWj(Pd) + GfbxW(OH)) + nTD + (function rA(){return mdO;}()) + A" ascii
    $s18 = "s[(function ERwL(){return ib;}()) + Y(HwhS) + (function sXEZ(){return od;}())]();var juU = Eh[(function wDc(){return Eq;}()) + (" ascii
    $s19 = "urn zPQck;}()) + (function E0(){return WZCXW;}()) + BWNnK(dg), false);Ar[(function Uvdl(){return Ykcbv;}())]();while (Ar[(functi" ascii
    $s20 = "urn iRRG;}()) + d(tL);};function Mb(){return 22;};function GKtA(){var Eh = new this[(function JhVYd(){return ib;}()) + HwhS + od" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}