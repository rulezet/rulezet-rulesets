rule sig_20160321_241d2cfff20322d44a30a254dd488c56 {
  meta:
    description = "datamaliciousorder - file 20160321_241d2cfff20322d44a30a254dd488c56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3629663c0c05195213b0e4b1ce1a307c6a6e3ed93753b1e80662d3f2739e1413"

  strings:
    $s1  = "var SMeYL = \"162\";var xfHjz = \"\\x38368\";var Pz = \"\\x32\\x31\";function Z(EXir){return EXir;};var mu = \"\\x66\";var p0 = " ascii
    $s2  = ")) + O(c0) + sK + (function les(){return hpof;}()) + (function OHj(){return Ep;}()) + d1(MR) + f0(h)]();WScript[lh(EUe) + (funct" ascii
    $s3  = "ch(e){};}LbT = WScript[Ge()](HS(k) + uAXvR(pLB) + (function K(){return GQ;}()) + (function F(){return N2;}()) + y(o1));LbT[(nuqH" ascii
    $s4  = " + (function eeNg(){return MR;}()) + (function rnCl(){return h;}())]();WScript[f1(EUe) + LuwT + (function nj(){return B0;}())](f" ascii
    $s5  = "(function slHi(){return rH;}()) + (function MHxf(){return ce;}()); XzX = bARn(); XFn = WScript[mwxyb(DZga) + (function Tz(){retu" ascii
    $s6  = "Cr\";var DHu = function UaqH() {return WScript[XFBp(DZga) + foZb + nMgs + Zn(VXmle) + (function z(){return buG;}())](d(c) + L0 +" ascii
    $s7  = "t\"](4);var Ynq = \"w\\x77.d\\x65\";var aeXl = \"\\x3a//\\x77\";var IqoP = \"http\";var Ud = \"GET\";function ZKjw(AoSP){return " ascii
    $s8  = " pj - oStmC;};function Ge(){return rVNCc(DZga) + (function xzi(){return foZb;}()) + vcvv(nMgs) + VXmle + buG;};function fjuA(){r" ascii
    $s9  = "ion So(){return pqCL;}())] < 4 ) {WScript[(function PBUt(){return EUe;}()) + C(LuwT) + vy(B0)](fjuA() * 10)};KyGXY = false;} cat" ascii
    $s10 = " = \"\\x69\\x6cli\\x73\";var yuEI = \"getM\";var H = \"\\x44ate\";function lh(IlJrL){return IlJrL;};function f1(dNhh){return dNh" ascii
    $s11 = "ion r2(){return Y0;}()) + (function jcm(){return u0;}()) + v ? (function XcG(){return ymumd;}()) + Z(ul) + p0 + mu : (function S" ascii
    $s12 = "juA());var nUVK = new this[DvVR + (function wT(){return HOmyr;}()) + (function E(){return xpXn;}())]();var LJkI = nUVK[(function" ascii
    $s13 = "d + UZjA(gqEht))]();LbT[(function qi(){return iks;}())] = 1;LbT[WnhI(SIiT) + (function A(){return WQJt;}())](XFn[Yp + I0(cs) + S" ascii
    $s14 = "v), false);XFn[EN(tOvX) + L1(eeI)]();while (XFn[P + Hq + aVP(ACo) + albG + (function EsT(){return giJkM;}()) + hYF(nMV) + (funct" ascii
    $s15 = "nction hiC(){return fWIZT;}()) + wq]((function OfP(){return FU;}()) + xpKY(x0) + Lg) + JkHC + (function tTiC(){return oz;}()) + " ascii
    $s16 = " CjjeB(){return ZdvdZ;}()) + xwGtr(c0) + sK + hpof + (function OWbW(){return Ep;}()) + MR + h]();var tQ = \"nenpx\";tQ = GHYq(Be" ascii
    $s17 = "ion yb(){return LuwT;}()) + (function XnXUt(){return B0;}())](fjuA());var nUVK = new this[ADw(DvVR) + HOmyr + (function pooWO(){" ascii
    $s18 = "turn Xn;}())](Lram, 2 );LbT[(function mL(){return J0;}()) + (function i(){return Y;}())]();lkWm(Lram);tQ = \"\" + SFC + NaJSA(Uu" ascii
    $s19 = "rn foZb;}()) + QMoyb(nMgs) + viD(VXmle) + buG](XzX); var KyGXY = true; while (KyGXY){try {XFn[(function o0(){return nuqHd;}()) +" ascii
    $s20 = "return xpXn;}())]();var Befya = nUVK[B(ZdvdZ) + (function r(){return c0;}()) + ZCJ(sK) + hpof + (function WLqDC(){return Ep;}())" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}