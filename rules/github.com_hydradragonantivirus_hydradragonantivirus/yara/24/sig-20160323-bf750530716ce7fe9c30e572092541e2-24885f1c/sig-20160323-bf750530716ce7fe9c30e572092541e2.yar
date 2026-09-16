rule sig_20160323_bf750530716ce7fe9c30e572092541e2 {
  meta:
    description = "datamaliciousorder - file 20160323_bf750530716ce7fe9c30e572092541e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dfa045225b454c7c9502c1c2f7abab10961c6f641fb2a7e143cf5f7a38f07f9"

  strings:
    $s1  = "function GG(CmK){var _112crap = \"s\"; return \"\" + CmK + \"\";};function HL(HO){var _112crap = \"s\"; return \"\" + HO + \"\";" ascii
    $s2  = "e);};}function G(Vd) {var TJs = (1, 2, 3, 4, 5, Vd); return TJs;};W = (wl) ? 14134 : 414234;cGb = WScript[w0()](N4(lZq) + Iw + s" ascii
    $s3  = "s[SoB(qe)](),T = MS[E0 + D1(P0) + s(Y0) + KSH(sg) + g0(j0) + u]();WScript[Ge(Znr)](iyA());var MS = new this[M(qe)](),MCl = MS[YE" ascii
    $s4  = "\"Ob\\x6ae\";var S = \"r\\x65a\\x74e\",rR = \"\\x43\";var qBj = false,Ol = function H() {return WScript[X(rR) + VB(S) + WN(pl) +" ascii
    $s5  = "(){var MS = new this[lns(qe)](),dWE = MS[Rc(E0) + up(P0) + Y0 + Gg(sg) + j0 + Lg(u)]();WScript[GSy(Znr)](iyA());var MS = new thi" ascii
    $s6  = " Jz(cs) + Ha(aC) + eUo(fk) + gq(Jc);};function i(o, JV){return o - JV;};function w0(){return tA(rR) + h0(S) + pl + ZDu(H1) + o0(" ascii
    $s7  = ";if (wl && sbs() && H0){function h() {return Ol[Ejf(R0) + bNj(cI) + kvy(aze) + o1(c) + tk(w2) + V(hHz) + H4(VZn)](c0(ITI) + Dd(x" ascii
    $s8  = ";var peH = \"QXC\",mV = \".exe\";var PSX = \"J\\x72\",o2 = \"QKSTb\";var HKI = \"5W\",J0 = \"mX\";var Fo = peH[\"cha\"+\"\\x72\"" ascii
    $s9  = "; H0 = true; D = \"07t9gasdf76ags\" + 123313 * W + D; break;}}function sbs() {return ((wl == H0) && (wl == true)) ? true : false" ascii
    $s10 = " {WScript[Znr](iyA() * 10)};Giz = false;} catch(wZ){Giz = (rO(J1) + ni(P2) + gq0(h3), Tm + A0(SR) + Hq(f0), TqG(R1) + vA(U), tru" ascii
    $s11 = "\\x67\";function lns(Qgx){var _112crap = \"s\"; return \"\" + Qgx + \"\";};function SoB(HcY){var _112crap = \"s\"; return \"\" +" ascii
    $s12 = "\\x73\\x65\",v0 = \"cl\\x6f\";function N5(HsW){var _112crap = \"s\"; return \"\" + HsW + \"\";};function jBS(Cq){var _112crap = " ascii
    $s13 = "s\"; return \"\" + dOx + \"\";};function Ha(H3){var _112crap = \"s\"; return \"\" + H3 + \"\";};function eUo(D0){var _112crap = " ascii
    $s14 = "DQ(mL)](jAP(a0) + Np + zr(ELX) + kW(fxW) + j(EJ) + Y);}();function w(G0){Ol[Wi + B(I)](G0, 0, 0);};function Pzb(){return UM(K) +" ascii
    $s15 = "var _112crap = \"s\"; return \"\" + i1 + \"\";};function Lg(ki){var _112crap = \"s\"; return \"\" + ki + \"\";};function D1(eF){" ascii
    $s16 = "_112crap = \"s\"; return \"\" + Vnh + \"\";};function I3(Lb){var _112crap = \"s\"; return \"\" + Lb + \"\";};var qi = \"ion\",Bf" ascii
    $s17 = "e\\x4f\";var X0 = \"C\\x72\\x65\";function tle(nKU){var _112crap = \"s\"; return \"\" + nKU + \"\";};function vkl(tqr){var _112c" ascii
    $s18 = " + UR + \"\";};function Nzq(f){var _112crap = \"s\"; return \"\" + f + \"\";};function odc(K2){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "+ \"\";};function kW(IXW){var _112crap = \"s\"; return \"\" + IXW + \"\";};function j(l){var _112crap = \"s\"; return \"\" + l +" ascii
    $s20 = "{var _112crap = \"s\"; return \"\" + S2 + \"\";};function ni(Aja){var _112crap = \"s\"; return \"\" + Aja + \"\";};function gq0(" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}