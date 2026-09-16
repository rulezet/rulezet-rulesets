rule sig_20160321_7551de8d35eff0d66829b7b00b2f876a {
  meta:
    description = "datamaliciousorder - file 20160321_7551de8d35eff0d66829b7b00b2f876a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42200b55a2d85b4a0b2bc187ff3fa9ecff2751a2f9bd0fc9a8d6c8ffcf28ac8c"

  strings:
    $s1  = "function R2(lezX){return lezX;};function P0(JxMd){return JxMd;};var tL = \"\\x32\";var Hmvvn = \"81\\x36\";var EOZ = \"\\x3183" ascii
    $s2  = "ion j(){return lEZ;}()); H = eTxz(); lc = WScript[TgXi(XER) + cesC(mXKs) + Y(mIt) + (function Pg(){return cF;}())](H); var jVD =" ascii
    $s3  = "n JQ(){return DvG;}()) + lD(d0) + (function c(){return sUwK;}())]();WScript[(function zRsCX(){return fjccZ;}()) + NArP(WLIN) + (" ascii
    $s4  = "It = \"e\\x4fbj\\x65\";var mXKs = jLuX[\"cha\\x72A\\x74\"](4);var XER = \"C\\x72e\\x61\";var bR = function YXFu() {return WScrip" ascii
    $s5  = ") + DvG + (function nWUsy(){return d0;}()) + (function pQRI(){return sUwK;}())]();WScript[(function Qmuj(){return fjccZ;}()) + W" ascii
    $s6  = "ction kXn(){return e;}()) + fUFp(QO) + mRSj;};function X(K, G){return K - G;};function Kah(){return XER + (function C(){return m" ascii
    $s7  = "Wf;}())] < 4 ) {WScript[bCn(fjccZ) + WLIN + n0(aTLC)](QiEd() * 10)};jVD = false;} catch(e){};}s = WScript[Kah()](Qm(gQfU) + ZO(L" ascii
    $s8  = ")]();var IhOAV = yyTn[pg(gcqn) + PIA(hmiSI) + (function f0(){return tz;}()) + (function DoJ(){return lF;}()) + za(G0) + (functio" ascii
    $s9  = "(mXKs) + mIt + ueA(cF)]((function XsMBp(){return Ls;}()) + oCcO(qs) + eF + (function qO(){return aI;}()));}();function druoz(dUt" ascii
    $s10 = " true; while (jVD){try {lc[QT]((function T1(){return C0;}()), (function zf(){return rt;}()) + x + (function MR(){return gLt;}())" ascii
    $s11 = ") + Cge(guHv) + ZhN(jfRh) + rm(Xz) + (function sSDDr(){return Wt;}()) + T ? (function V0(){return lsxJA;}()) + (function ATs(){r" ascii
    $s12 = "function UWp(){return aTLC;}())](QiEd());var yyTn = new this[(function VIbkf(){return rF;}()) + (function zyg(){return rn;}())](" ascii
    $s13 = "QE){bR[(function yqv(){return Lg;}())](dUtQE, 0, 0);};function eTxz(){return (function Nc(){return Ngg;}()) + ZTaid(twaB) + (fun" ascii
    $s14 = "on SO(){return G0;}()) + DvG + (function sYo(){return d0;}()) + (function UajB(){return sUwK;}())]();var PZp = \"TGUWM\";PZp = X" ascii
    $s15 = ");var uORx = yyTn[n(gcqn) + (function f1(){return hmiSI;}()) + (function fs(){return tz;}()) + lF + (function G1(){return G0;}()" ascii
    $s16 = "(C1) + (function nXc(){return NJDzs;}())]();druoz(OqTa);PZp = \"\" + i(ecWsX) + pKC(xocQ) + m0 + rT(YcU) + My(P) + (function bci" ascii
    $s17 = "turn Ph;}())]);s[(function q(){return sbkTj;}()) + U(oY)] = 0;s[K0(G3) + (function VNYKj(){return X2;}()) + H2](OqTa, 2 );s[vPRk" ascii
    $s18 = "LIN + z(aTLC)](QiEd());var yyTn = new this[(function F(){return rF;}()) + rn]();var f = yyTn[gcqn + hmiSI + k(tz) + lF + (functi" ascii
    $s19 = "+ (function x0(){return m;}()) + cwYYU(xLjD), false);lc[nmnMn(MAJ)]();while (lc[uAvtu(OPmSn) + cdqK + (function PFUed(){return M" ascii
    $s20 = "XKs;}()) + NI(mIt) + (function CDYt(){return cF;}());};function QiEd(){return 22;};function YpI(){var yyTn = new this[rF + Zd(rn" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}