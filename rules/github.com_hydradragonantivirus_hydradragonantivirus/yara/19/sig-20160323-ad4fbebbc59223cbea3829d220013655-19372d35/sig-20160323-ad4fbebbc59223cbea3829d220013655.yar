rule sig_20160323_ad4fbebbc59223cbea3829d220013655 {
  meta:
    description = "datamaliciousorder - file 20160323_ad4fbebbc59223cbea3829d220013655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a220051211770131f3a8144dbc324043b3c13ef0339725f61e20080635300d0a"

  strings:
    $s1  = "Script[jtI()](h1 + kVf(AW0) + rCR + SMN(kSx) + S1(cQj));g = wIV;h0 = (wFi) ? Q : h0;g[(Bo(t2) + pjc(Yf))]();h0 = (wFi) ? Q : h0;" ascii
    $s2  = "+ f(AR) + k(j1) + xwc;};function OCZ(zK, ouf){return zK - ouf;};function jtI(){return co + MnK(Qq) + op(NBe) + W0(ru) + Ju(roV);" ascii
    $s3  = "s\" + 123313 * Q + h0; break;}}function RSk() {return ((ujv == wFi) && (ujv == true)) ? true : false;};if (ujv && RSk() && wFi){" ascii
    $s4  = "S = new this[E0(caL) + M(s0)](),j = S[w(m) + Qgk(TGV) + cHZ(InR) + az(jZ)]();WScript[sQ](h());var S = new this[tR(caL) + vK(s0)]" ascii
    $s5  = "(),mKG = S[m + B(TGV) + InR + T(jZ)]();WScript[SyR(sQ)](h());var S = new this[u(caL) + E1(s0)](),NR = S[pu(m) + WF(TGV) + wcI(In" ascii
    $s6  = "var ru = \"j\\x65c\",NBe = \"te\\x4fb\";var Qq = \"ea\",co = \"Cr\";var nn = false,Md = function H() {return WScript[co + Xca(Qq" ascii
    $s7  = "+ Rf] < 4 ) {WScript[PTa(sQ)](h() * 10)};RaU = false;} catch(yGz){RaU = (A0(ViW) + WAU + nE(u2) + Zxz, lD(r) + PiM(w1) + zP(QE) " ascii
    $s8  = "\\x73e\\x6e\\x64\";function o1(lyg){var _112crap = \"s\"; return \"\" + lyg + \"\";};function X0(l0){var _112crap = \"s\"; retur" ascii
    $s9  = "function vSo(KfV){var _112crap = \"s\"; return \"\" + KfV + \"\";};function wsa(VIA){var _112crap = \"s\"; return \"\" + VIA + " ascii
    $s10 = "_112crap = \"s\"; return \"\" + B0 + \"\";};var kSm = \"YPMcG0bOx\",AW = \"E\\x54\";var T0 = kSm[\"cha\"+\"\\x72\"+\"\"+\"\\x41" ascii
    $s11 = "turn \"\" + j2 + \"\";};function nc(gR){var _112crap = \"s\"; return \"\" + gR + \"\";};function Fi(D0){var _112crap = \"s\"; re" ascii
    $s12 = "nction ziY(q1){var _112crap = \"s\"; return \"\" + q1 + \"\";};function Fmc(mM){var _112crap = \"s\"; return \"\" + mM + \"\";};" ascii
    $s13 = "ar s = 0; s < h() * 1; s++){if (yRb() != 0){ujv = true; h0 = \"07t9gasdf76ags\" + 123313 * Q + h0; wFi = true; h0 = \"07t9gasdf7" ascii
    $s14 = "R) + SVv(jZ)]();var Q = \"F\";Q = OCZ(mKG, j);var h0 = \"W\";h0 = OCZ(NR, mKG);return OCZ(Q, h0);}var ujv = false,wFi = false;fo" ascii
    $s15 = "112crap = \"s\"; return \"\" + ut + \"\";};function S1(Av){var _112crap = \"s\"; return \"\" + Av + \"\";};var Ekp = \"m7\",cQj " ascii
    $s16 = "tion SD(jm){var _112crap = \"s\"; return \"\" + jm + \"\";};function Lx(f2){var _112crap = \"s\"; return \"\" + f2 + \"\";};func" ascii
    $s17 = "){var _112crap = \"s\"; return \"\" + mNL + \"\";};function W0(YsZ){var _112crap = \"s\"; return \"\" + YsZ + \"\";};function Ju" ascii
    $s18 = " G0(b0){var _112crap = \"s\"; return \"\" + b0 + \"\";};function rg0(QJR){var _112crap = \"s\"; return \"\" + QJR + \"\";};funct" ascii
    $s19 = "Lx(V) + F1(wLM) + XI(SbZ) + MV(wX) + sDm(Os) + vk(ZxP) + py(u1) + Smu(yu), false);KBv[UpX(FGL)]();while (KBv[hr + MYM + ss + E2 " ascii
    $s20 = "2crap = \"s\"; return \"\" + Lr + \"\";};function a(K){var _112crap = \"s\"; return \"\" + K + \"\";};function x(Tn){var _112cra" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}