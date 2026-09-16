rule sig_20160323_4d65fedb3a01c9eeb240f5950e0f7a8f {
  meta:
    description = "datamaliciousorder - file 20160323_4d65fedb3a01c9eeb240f5950e0f7a8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa6cde5f12c6ddca517cbef68bc71162e6dc94e86b0ddd4035e729588a01907c"

  strings:
    $s1  = ", sQ); return HzM;};BK = (coq) ? 14134 : 414234;ToV = WScript[OOQ()](qCD + t0 + N2 + bv(mYd));N = ToV;hi = (vjL) ? BK : hi;N[(eV" ascii
    $s2  = "r HN = false,W = function Mn() {return WScript[M(vbQ) + FI(tlU) + XHf + eMA(No)](UAk(c) + swQ + Ug + Cg(inb) + fM(qmo));}();func" ascii
    $s3  = "function ouv(s2){var _112crap = \"s\"; return \"\" + s2 + \"\";};var yC = \"cl\\x6fse\";function hK(bl){var _112crap = \"s\"; re" ascii
    $s4  = "+ T(A) + B(CY) + MQ(k2) + R0(US) + j(O)]();WScript[pd(geQ) + bq(x)](K());var wXS = new this[hCg](),Dky = wXS[b0 + S(QzN) + OV(A)" ascii
    $s5  = " + Y0(CY) + k3(k2) + Fd(US) + F(O)]();WScript[Z(geQ) + x](K());var wXS = new this[fa(hCg)](),TO = wXS[bbp(b0) + h0(QzN) + l0(A) " ascii
    $s6  = "se;};if (coq && WeG() && vjL){function k() {return W[T0 + CnB(Arv) + bSJ + bC(J) + M0(e0) + n(NtP) + Z0(lNK) + OeA(yv)](Qf(c1) +" ascii
    $s7  = " \"Run\";function UAk(h){var _112crap = \"s\"; return \"\" + h + \"\";};function Cg(Rj){var _112crap = \"s\"; return \"\" + Rj +" ascii
    $s8  = "jL = true; hi = \"07t9gasdf76ags\" + 123313 * BK + hi; break;}}function WeG() {return ((coq == vjL) && (coq == true)) ? true : f" ascii
    $s9  = "JYT(ZWM)]();while (UG[QcC(H1) + VK(da) + rN(Cya)] < 4 ) {WScript[geQ + wbA(x)](K() * 10)};Bqx = false;} catch(XV){Bqx = (qb(JoT)" ascii
    $s10 = "+\"At\"](1);var k2 = \"on\",CY = \"\\x73e\\x63\";var A = \"\\x4d\\x69\\x6cli\",QzN = \"TC\";var b0 = \"getU\";function UQC(dc){v" ascii
    $s11 = "eturn \"\" + Q + \"\";};function Fd(MK){var _112crap = \"s\"; return \"\" + MK + \"\";};function F(JVj){var _112crap = \"s\"; re" ascii
    $s12 = ";function L(VlB){var _112crap = \"s\"; return \"\" + VlB + \"\";};var a = \"dy\",rf = \"\\x6es\\x65\\x42o\";var UuL = \"po\",O1 " ascii
    $s13 = "= \"s\"; return \"\" + c2 + \"\";};function Dl(uy){var _112crap = \"s\"; return \"\" + uy + \"\";};function c3(d1){var _112crap " ascii
    $s14 = "j + \"\";};function bbp(i){var _112crap = \"s\"; return \"\" + i + \"\";};function h0(mN){var _112crap = \"s\"; return \"\" + mN" ascii
    $s15 = "){var _112crap = \"s\"; return \"\" + f + \"\";};function S(Wn){var _112crap = \"s\"; return \"\" + Wn + \"\";};function OV(Wzh)" ascii
    $s16 = "};function n(NG){var _112crap = \"s\"; return \"\" + NG + \"\";};function Z0(nUI){var _112crap = \"s\"; return \"\" + nUI + \"\"" ascii
    $s17 = "ar _112crap = \"s\"; return \"\" + pP + \"\";};var uLQ = \"ldaITu1\",mV = \"E4sDe\";var O = mV[\"cha\"+\"\\x72\"+\"At\"](2),US =" ascii
    $s18 = "n FJY(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};var LJk = \"\\x77ri\\x74\\x65\";function o(hal){var _112crap = \"s\"; " ascii
    $s19 = "\" + lx + \"\";};function T(nmV){var _112crap = \"s\"; return \"\" + nmV + \"\";};function B(q){var _112crap = \"s\"; return \"" ascii
    $s20 = " = \"\\x44a\";function pd(Vo){var _112crap = \"s\"; return \"\" + Vo + \"\";};function bq(yrT){var _112crap = \"s\"; return \"\"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}