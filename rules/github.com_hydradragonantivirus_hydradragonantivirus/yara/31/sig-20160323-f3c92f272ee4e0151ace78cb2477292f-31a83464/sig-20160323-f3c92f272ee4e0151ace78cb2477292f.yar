rule sig_20160323_f3c92f272ee4e0151ace78cb2477292f {
  meta:
    description = "datamaliciousorder - file 20160323_f3c92f272ee4e0151ace78cb2477292f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82ee459479e5f844af73e63d58a7e495ae2716da40bd24a495e36c900d017a82"

  strings:
    $s1  = "function ptS(Be){var _112crap = \"s\"; return \"\" + Be + \"\";};var e2 = \"e\",T0 = \"\\x63los\";function YU(LF){var _112crap =" ascii
    $s2  = "F(B0), rWV(IQ) + Iv, true);};}function iO(n) {var FA = (1, 2, 3, 4, 5, n); return FA;};xvP = (A) ? 14134 : 414234;OR = WScript[L" ascii
    $s3  = "+ aSQ(Ve) + Jjo(iGk) + ry;}; oVF = pJ(); pJ0 = WScript[S + ZMt(jZ) + y(o)](oVF); var i = true; while (i){try {pJ0[i3](t0(Jt), IK" ascii
    $s4  = "r xvP = 0,FYk = 0;function YV(){var Qw = new this[bu](),xQg = Qw[v0(KJ) + b(Zoe) + Z(M0) + T(S0) + W(Zzq) + z + A0]();WScript[G1" ascii
    $s5  = " = false;var pgn = function PDv() {return WScript[Aj(S) + jZ + Qmr(o)](D + k0 + nV(kA) + g + v);}();function f(mcs){pgn[s(IyC) +" ascii
    $s6  = "a\";var zH = \"\\x74\\x70\\x3a\\x2f\\x2f\",Cjt = \"\\x68t\";function t0(IsO){var _112crap = \"s\"; return \"\" + IsO + \"\";};va" ascii
    $s7  = " mHE(snw)](mcs, 0, 0);};function pJ(){return x + lVZ + iL(KQ) + i1(bZR) + Do(q);};function M(Nl, UB){return Nl - UB;};function L" ascii
    $s8  = "3 * xvP + FYk; break;}}function IY() {return ((A == Vo) && (A == true)) ? true : false;};if (A && IY() && Vo){function Mly() {re" ascii
    $s9  = "J0[nG(EY) + j2(K) + g3(tKo)] < 4 ) {WScript[st + lXK](otr() * 10)};i = false;} catch(QgL){i = (yvk + YyC(e1), R(I1) + D1(cgx) + " ascii
    $s10 = "\\x45MP\",Li = Ejz[\"cha\"+\"\\x72\"+\"At\"](0);function auq(qpT){var _112crap = \"s\"; return \"\" + qpT + \"\";};function s0(g" ascii
    $s11 = ",D0 = \"\\x6fn\";var NGA = \"\\x73e\\x63\",DWH = \"Mill\\x69\";var va = \"\\x43\",vt = \"getUT\";var eAy = \"te\",uO = \"D\\x61" ascii
    $s12 = " \"s\"; return \"\" + ne + \"\";};function i0(G){var _112crap = \"s\"; return \"\" + G + \"\";};function ZMt(a){var _112crap = " ascii
    $s13 = "ap = \"s\"; return \"\" + A2 + \"\";};function ERJ(Fsc){var _112crap = \"s\"; return \"\" + Fsc + \"\";};var Sqg = \"\\x65\",kd " ascii
    $s14 = "1 = \"d\\x66a\",yvk = \"a\\x73\";var Aa = \"le\\x65p\",U = \"\\x53\";function nG(ho){var _112crap = \"s\"; return \"\" + ho + \"" ascii
    $s15 = "ap = \"s\"; return \"\" + Gd + \"\";};function D1(Za){var _112crap = \"s\"; return \"\" + Za + \"\";};function F(mh){var _112cra" ascii
    $s16 = " \"s\"; return \"\" + cw + \"\";};function jqY(u){var _112crap = \"s\"; return \"\" + u + \"\";};var y0 = \"am\",Zp = \"\\x53tr" ascii
    $s17 = " rd + \"\";};function iCx(G3){var _112crap = \"s\"; return \"\" + G3 + \"\";};var k1 = \"cfB1u\",xs = \"yP0rvfjqQ\";var e = \"os" ascii
    $s18 = "nction v0(QO){var _112crap = \"s\"; return \"\" + QO + \"\";};function b(kx){var _112crap = \"s\"; return \"\" + kx + \"\";};fun" ascii
    $s19 = "\" + a + \"\";};function y(xI){var _112crap = \"s\"; return \"\" + xI + \"\";};var o = \"ct\",jZ = \"\\x65O\\x62\\x6ae\";var S =" ascii
    $s20 = ",IV = \"8vME\\x4c\";var bwC = \"1\\x33\";function gw(Av){var _112crap = \"s\"; return \"\" + Av + \"\";};function q0(oIP){var _1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}