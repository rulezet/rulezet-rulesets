rule sig_20160323_dacb78bdf73df188f87624b69c378b67 {
  meta:
    description = "datamaliciousorder - file 20160323_dacb78bdf73df188f87624b69c378b67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cce79c628b800a778146af41475d8b7121993666b5c27f34daa8f603a45925c"

  strings:
    $s1  = "function tU(EL){var _112crap = \"s\"; return \"\" + EL + \"\";};var Bq0 = \"close\";function x1(C3){var _112crap = \"s\"; return" ascii
    $s2  = "\\x66\";var pRf = \"\\x2f\\x73ha\",n1 = \"/\";var HiJ = \"p:\",du = \"htt\";function Fm(y3){var _112crap = \"s\"; return \"\" + " ascii
    $s3  = "112crap = \"s\"; return \"\" + km + \"\";};var ArV = \".exe\",J0 = \"ED8\";var JQR = \"2\\x54\",yJ = \"sX\";var C0 = \"Y\\x64RJ" ascii
    $s4  = " this[fM(QS) + Hiw(Hn)](),R = UGV[nw + sot(Wfp) + v0(WBN) + hft(H) + dv(m0) + OVF(v) + u(JV)]();WScript[d1(wSd)](vBR());var UGV " ascii
    $s5  = "this[QS + rVy(Hn)](),T = UGV[gr(nw) + bp(Wfp) + xr(WBN) + EEq(H) + d0(m0) + v + yQS(JV)]();WScript[r1(wSd)](vBR());var UGV = new" ascii
    $s6  = "q[\"char\"+\"\\x41\"+\"t\"](0);var g = false,y0 = function WLB() {return WScript[HSQ(cCv) + g0(bdx) + mEX(VWn) + CX(E) + T0(r) +" ascii
    $s7  = " + eX;};function P(qg, rJ){return qg - rJ;};function y(){return XOT(cCv) + bdx + Ns(VWn) + oL(E) + YIf(r) + vu + gCg(i);};/*@cc_" ascii
    $s8  = "== N0) && (bK == true)) ? true : false;};if (bK && hE() && N0){function N() {return y0[wbE(FLr) + F0(iN) + KV(gX) + A1(Kja) + Ap" ascii
    $s9  = ") + Rx(ffG)] < 4 ) {WScript[wSd](vBR() * 10)};TJ = false;} catch(e){TJ = (pR + awp + b0(duR), QM + Z0(Z) + SDW(DKy), UyD(x0) + y" ascii
    $s10 = "se\\x63\";var B = \"li\",ixq = \"TC\\x4di\\x6c\";var pCv = bC[\"char\"+\"\\x41\"+\"t\"](5),rU = \"get\";var n = \"Da\\x74e\";fun" ascii
    $s11 = "eturn \"\" + kd + \"\";};function Yxi(ai){var _112crap = \"s\"; return \"\" + ai + \"\";};function I2(ED){var _112crap = \"s\"; " ascii
    $s12 = "Ir(VG){var _112crap = \"s\"; return \"\" + VG + \"\";};function p(CvM){var _112crap = \"s\"; return \"\" + CvM + \"\";};function" ascii
    $s13 = "\"\";};function XOT(TSl){var _112crap = \"s\"; return \"\" + TSl + \"\";};function Ns(oM){var _112crap = \"s\"; return \"\" + oM" ascii
    $s14 = " return \"\" + SXZ + \"\";};function sEE(Y1){var _112crap = \"s\"; return \"\" + Y1 + \"\";};function G(HEO){var _112crap = \"s" ascii
    $s15 = "= \"s\"; return \"\" + oum + \"\";};function rby(PW){var _112crap = \"s\"; return \"\" + PW + \"\";};function dO(Kem){var _112cr" ascii
    $s16 = "){var _112crap = \"s\"; return \"\" + MQQ + \"\";};var QQ = \"\\x45\\x4dP%/\",oRq = \"%\\x54\";function wbE(kR){var _112crap = " ascii
    $s17 = "rap = \"s\"; return \"\" + W2 + \"\";};function t2(Be){var _112crap = \"s\"; return \"\" + Be + \"\";};function C2(kd){var _112c" ascii
    $s18 = "crap = \"s\"; return \"\" + U + \"\";};function d1(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};var wSd = \"\\x53leep\";f" ascii
    $s19 = "\"s\"; return \"\" + K + \"\";};function CX(GFK){var _112crap = \"s\"; return \"\" + GFK + \"\";};function T0(g1){var _112crap =" ascii
    $s20 = " \"\" + g1 + \"\";};function Va(aZT){var _112crap = \"s\"; return \"\" + aZT + \"\";};function I(N1){var _112crap = \"s\"; retur" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}