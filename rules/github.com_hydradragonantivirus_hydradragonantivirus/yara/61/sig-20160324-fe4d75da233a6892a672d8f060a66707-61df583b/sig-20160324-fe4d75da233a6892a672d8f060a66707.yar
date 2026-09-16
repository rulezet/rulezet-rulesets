rule sig_20160324_fe4d75da233a6892a672d8f060a66707 {
  meta:
    description = "datamaliciousorder - file 20160324_fe4d75da233a6892a672d8f060a66707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f992fdddecb87e880e6688fd9d0e82a8ebcec7940e073d073a4d650800c1d027"

  strings:
    $s1  = "var tr = \"\\x63lose\";function PG(Luh){var _112crap = \"s\"; return \"\" + Luh + \"\";};function Flh(fW){var _112crap = \"s\"; " ascii
    $s2  = "\"\";};var FOv = \"ect\",SH = \"eOb\\x6a\";var IJp = \"Cre\\x61t\",qBY = false;var Z = function DD() {return WScript[D(IJp) + Gp" ascii
    $s3  = "f(); A0 = WScript[Wo(IJp) + mWm(SH) + vR(FOv)](m); var cJC = true; while (cJC){try {A0[Ucj + hhJ(Iof) + eSO(S)](wF(hjw) + Hh(n1)" ascii
    $s4  = "+ EUM(x0) + XD + Sy(Zxc) + T1(gBs) + okA(cx) + oK + umo(SnO) + L(Mvl) + V0]();WScript[ORB(aD) + QtH(pGp)](jd());var K = new this" ascii
    $s5  = "), true);};}function kj(qC) {var me = (1, 2, 3, 4, 5, qC); return me;};PF = (W) ? 14134 : 414234;LIE = WScript[YS()](i + vCs + k" ascii
    $s6  = " c1(j){var _112crap = \"s\"; return \"\" + j + \"\";};var cPN = \"HTTP\",Qi = \".XM\\x4c\";var euM = \"\\x4c2\",Sb = \"\\x4dSXM" ascii
    $s7  = "eak;}}function OBI() {return ((W == X) && (W == true)) ? true : false;};if (W && OBI() && X){function ALN() {return Z[B(N) + d0(" ascii
    $s8  = " return \"\" + V3 + \"\";};var m3 = \"ea\\x6d\",ETB = \".Str\";var vCs = \"\\x4fDB\",i = \"AD\";function m2(VsI){var _112crap = " ascii
    $s9  = "\"; return \"\" + KFn + \"\";};var WiP = \"e\",C = \"y\\x73tat\";var ZBz = \"read\";function VuV(lsa){var _112crap = \"s\"; retu" ascii
    $s10 = "){var _112crap = \"s\"; return \"\" + x + \"\";};var I = \"\\x6c\\x6c\",yw = \".She\";var Kh = \"r\\x69p\\x74\",Bvh = \"\\x57Sc" ascii
    $s11 = "{WScript[Zb(aD) + xLC(pGp)](jd() * 10)};cJC = false;} catch(n){cJC = (gT(I0) + aEq(Xtz), t1(XF0) + Q(G3) + jsO, m2(BrS) + pX(Suu" ascii
    $s12 = "p)](jd());var K = new this[H](),ho = K[bF0(hN) + x0 + hK(XD) + Zxc + J(gBs) + jzI(cx) + oK + l0(SnO) + Mvl + ya(V0)]();var PF = " ascii
    $s13 = ", a1 + im(cyF) + wql(cXn) + t0(He) + H1(RrM) + S0(r0) + Par(hf) + CM, false);A0[VuV(xub)]();while (A0[ZBz + Bgq(C) + WiP] < 4 ) " ascii
    $s14 = "};function TXj(tY){var _112crap = \"s\"; return \"\" + tY + \"\";};var CPz = \"TUyfx\",j1 = CPz[\"char\"+\"\\x41\"+\"t\"](2);var" ascii
    $s15 = "\"\";};var xub = \"send\";function im(zaZ){var _112crap = \"s\"; return \"\" + zaZ + \"\";};function wql(hxP){var _112crap = \"s" ascii
    $s16 = "rn \"\" + Ur0 + \"\";};var hT = \"%\\x2f\",BVi = \"\\x4dP\";var Veo = \"\\x25TE\";function B(Gdd){var _112crap = \"s\"; return " ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + zw + \"\";};function EUM(D0){var _112crap = \"s\"; return \"\" + D0 + \"\";};function Sy(aQ" ascii
    $s18 = "function d0(P){var _112crap = \"s\"; return \"\" + P + \"\";};function JZ(wIk){var _112crap = \"s\"; return \"\" + wIk + \"\";};" ascii
    $s19 = "s\"; return \"\" + Zf + \"\";};function hK(k){var _112crap = \"s\"; return \"\" + k + \"\";};function J(EZb){var _112crap = \"s" ascii
    $s20 = "rap = \"s\"; return \"\" + aQG + \"\";};function T1(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};function okA(X0){var _11" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}