rule sig_20160323_5b7da84b15bd65470972bf27ce5b2248 {
  meta:
    description = "datamaliciousorder - file 20160323_5b7da84b15bd65470972bf27ce5b2248.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f6dc1f3a1e2b227554d59eb7b7c520b9e9171cad61b17e615e9fb4202a2d601"

  strings:
    $s1  = "function Xa(N2){var _112crap = \"s\"; return \"\" + N2 + \"\";};function Yy(k4){var _112crap = \"s\"; return \"\" + k4 + \"\";};" ascii
    $s2  = "x70k\";var Wvj = \"7\",BEp = \"P\\x56q1\";function KjN(TDv){var _112crap = \"s\"; return \"\" + TDv + \"\";};var pVZ = \"%\\x2f" ascii
    $s3  = "F(W) + HLJ(zu)]();WScript[c0(HEz) + s](Xu());var hQf = new this[Li + eb(DK)](),Ej = hQf[CM(QPY) + v(Qx) + Q1(Ib) + hAL(r3) + GD(" ascii
    $s4  = "), j0(U1) + pZO, true);};}function qT(nF) {var Uuf = (1, 2, 3, 4, 5, nF); return Uuf;};mH = (l) ? 14134 : 414234;Q = WScript[FUJ" ascii
    $s5  = " wJE(Qo) + iE(C0);}; IuC = GCk(); GoJ = WScript[y(TO) + P(lE) + CH(eA) + LL(un) + Hv](IuC); var zNw = true; while (zNw){try {GoJ" ascii
    $s6  = "qbl) + MJv(W) + C(zu)]();WScript[I(HEz) + B(s)](Xu());var hQf = new this[mv(Li) + NBi(DK)](),xH = hQf[J(QPY) + K1(Qx) + U0(Ib) +" ascii
    $s7  = "[osd](ZRw(iO) + EAV(M2), nsP + C1(T0) + x1(P0) + Qzq(Kgy) + q(F0) + nK + rs(Q3) + RDV(nk) + Jb(irC) + EC, false);GoJ[dw0(qjz)]()" ascii
    $s8  = "j, 0, 0);};function GCk(){return D + OEB(MM) + Wkx + Qzm(H) + R(Z1);};function XI(Z0, DyB){return Z0 - DyB;};function FUJ(){retu" ascii
    $s9  = "AE = \"07t9gasdf76ags\" + 123313 * mH + hAE; break;}}function U() {return ((l == zJ) && (l == true)) ? true : false;};if (l && U" ascii
    $s10 = ";while (GoJ[zx(Z2) + lka] < 4 ) {WScript[UUh(HEz) + tm(s)](Xu() * 10)};zNw = false;} catch(fG){zNw = (ZLB(FvX), T1 + QjK + J1(yz" ascii
    $s11 = "2\"+\"At\"](2);var Agp = \"\\x6c\\x69\\x73ec\",a = \"\\x43\\x4dil\";var YfD = \"getUT\",YB = \"\\x44ate\";function c0(PU){var _1" ascii
    $s12 = "= \"\\x6fFi\\x6c\";var p0 = \"SaveT\";function ZI(X0){var _112crap = \"s\"; return \"\" + X0 + \"\";};function iyo(b3){var _112c" ascii
    $s13 = " mxx(r3) + l0(qbl) + W + zu]();var mH = \"JH\";mH = XI(Ej, wIC);var hAE = \"pjt\";hAE = XI(xH, Ej);return XI(mH, hAE);}var l = f" ascii
    $s14 = "nction y(Ex){var _112crap = \"s\"; return \"\" + Ex + \"\";};function P(IM){var _112crap = \"s\"; return \"\" + IM + \"\";};func" ascii
    $s15 = "= \"s\"; return \"\" + JTE + \"\";};function R(aE){var _112crap = \"s\"; return \"\" + aE + \"\";};var Z1 = \"HT\\x54P\",H = \"M" ascii
    $s16 = " \"s\"; return \"\" + X + \"\";};function hAL(mE){var _112crap = \"s\"; return \"\" + mE + \"\";};function GD(MS){var _112crap =" ascii
    $s17 = " iE(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};var TM = \"eQmOl.e6\",C0 = \"exe\";var Qo = TM[\"cha\"+\"\\x72\"+\"At\"]" ascii
    $s18 = "ar _112crap = \"s\"; return \"\" + bdN + \"\";};function v(DU){var _112crap = \"s\"; return \"\" + DU + \"\";};function Q1(X){va" ascii
    $s19 = "eturn \"\" + b3 + \"\";};var Czu = \"n\",tM = \"io\";var Q4 = \"posi\\x74\";function ew(VW){var _112crap = \"s\"; return \"\" + " ascii
    $s20 = "at\\x65\",Z2 = \"r\\x65ady\";function dw0(bX){var _112crap = \"s\"; return \"\" + bX + \"\";};var qjz = \"se\\x6ed\";function C1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}