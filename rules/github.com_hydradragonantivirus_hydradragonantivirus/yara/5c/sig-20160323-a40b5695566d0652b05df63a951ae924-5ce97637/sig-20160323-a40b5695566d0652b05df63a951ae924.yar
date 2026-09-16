rule sig_20160323_a40b5695566d0652b05df63a951ae924 {
  meta:
    description = "datamaliciousorder - file 20160323_a40b5695566d0652b05df63a951ae924.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8098dc228f17b09bb37457007fa482a1c2b435127654f7838f81bd0a0dbac4d"

  strings:
    $s1  = "var Z = 0,cN = 0;function EX(){var SI = new this[v0(a) + BC](),knF = SI[vlK(r1) + bU + yoX(D0) + lYO + rEz(t0)]();WScript[t1](hm" ascii
    $s2  = " + afi(qI) + pr + x0 + iJ(uw) + Gs, false);c[ZZn(Kmb) + ZMV]();while (c[J2 + yvl(tw) + zxo(Eg)] < 4 ) {WScript[bAo(t1)](hm() * 1" ascii
    $s3  = "\"cha\"+\"\\x72\"+\"\"+\"\\x41\"+\"t\"](4),LpX = \"e\";var fsF = \"t\",v = \"Cre\\x61\";var jFa = false,Q = function NB() {retur" ascii
    $s4  = "());var SI = new this[KoF(a) + a0(BC)](),Xi = SI[r1 + bU + qH(D0) + g0(lYO) + aJ(t0)]();WScript[M(t1)](hm());var SI = new this[U" ascii
    $s5  = "4, 5, U); return iA;};Z = (k) ? 14134 : 414234;mA = WScript[B()](c1(f) + r2(M1) + lfQ(qpD) + wX(bI));B0 = mA;cN = (q) ? Z : cN;B" ascii
    $s6  = "function TyU(){return HSA(NcZ) + t + ks(CX) + RO + AY;};function qw(J, K){return J - K;};function B(){return v + XP(fsF) + uuM(L" ascii
    $s7  = " 123313 * Z + cN; q = true; cN = \"07t9gasdf76ags\" + 123313 * Z + cN; break;}}function JA() {return ((k == q) && (k == true)) ?" ascii
    $s8  = "M\\x53X\";function GE(FkI){var _112crap = \"s\"; return \"\" + FkI + \"\";};var g = \"Run\";function hWv(s){var _112crap = \"s\"" ascii
    $s9  = "rue : false;};if (k && JA() && q){function xXD() {return Q[z0(TF) + Mv(Y) + BzP(txN) + jnW + ZNV(hc) + SY(m0) + GtY + Te + Ue0(J" ascii
    $s10 = "function C(Sl){var _112crap = \"s\"; return \"\" + Sl + \"\";};function GX(x2){var _112crap = \"s\"; return \"\" + x2 + \"\";};v" ascii
    $s11 = "\\x44\\x4f\";var o = \"\\x61\",OJ = \"\\x61f\\x64af\";function k3(L){var _112crap = \"s\"; return \"\" + L + \"\";};function Ln(" ascii
    $s12 = "\\x69le\",BR = \"oF\";var r3 = \"\\x53av\\x65T\";function INl(LVI){var _112crap = \"s\"; return \"\" + LVI + \"\";};function HwN" ascii
    $s13 = "\\x73\",dW = \"po\";function CNS(c2){var _112crap = \"s\"; return \"\" + c2 + \"\";};function Tr(Jhd){var _112crap = \"s\"; retu" ascii
    $s14 = "+ \"\";};function wX(Fp){var _112crap = \"s\"; return \"\" + Fp + \"\";};var bI = \"am\",qpD = \"\\x53\\x74\\x72\\x65\";var M1 =" ascii
    $s15 = "{var _112crap = \"s\"; return \"\" + WW + \"\";};function g0(sob){var _112crap = \"s\"; return \"\" + sob + \"\";};function aJ(n" ascii
    $s16 = "ction uuM(O){var _112crap = \"s\"; return \"\" + O + \"\";};function EEn(lFf){var _112crap = \"s\"; return \"\" + lFf + \"\";};f" ascii
    $s17 = " \"s\"; return \"\" + mUo + \"\";};function IR(IAt){var _112crap = \"s\"; return \"\" + IAt + \"\";};function afi(PRe){var _112c" ascii
    $s18 = "nction BhG(Nh){var _112crap = \"s\"; return \"\" + Nh + \"\";};function zKA(PII){var _112crap = \"s\"; return \"\" + PII + \"\";" ascii
    $s19 = "i);return qw(Z, cN);}var k = false,q = false;for (var r = 0; r < hm() * 1; r++){if (EX() != 0){k = true; cN = \"07t9gasdf76ags\"" ascii
    $s20 = "eturn \"\" + PRe + \"\";};function iJ(gTy){var _112crap = \"s\"; return \"\" + gTy + \"\";};var Gs = \"\\x61\",uw = \"s\";var x0" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}