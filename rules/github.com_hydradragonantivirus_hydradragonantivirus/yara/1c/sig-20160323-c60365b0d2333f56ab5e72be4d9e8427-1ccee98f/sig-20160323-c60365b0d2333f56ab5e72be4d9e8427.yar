rule sig_20160323_c60365b0d2333f56ab5e72be4d9e8427 {
  meta:
    description = "datamaliciousorder - file 20160323_c60365b0d2333f56ab5e72be4d9e8427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5e94acd1d7c5db927aca0bf82840f107e1f885b8365e9d0278cdd5776d3e34e"

  strings:
    $s1  = "function OO(LGi){var _112crap = \"s\"; return \"\" + LGi + \"\";};function AK(p1){var _112crap = \"s\"; return \"\" + p1 + \"\";" ascii
    $s2  = "x(kK) + KL(h0) + ht(qGh) + ZJM + hjU(u) + E0(wB)]();WScript[c2(b)](QRI());var R = new this[yw(zr) + pWZ(uMc) + uu(XW)](),g1 = R[" ascii
    $s3  = "y = \"\\x43reat\",hG = false;var ECX = function sxj() {return WScript[GWT(ky) + iV(rn) + uj](X(N) + A + zBj(EE) + sHM(y0));}();f" ascii
    $s4  = "[kK + NqX(h0) + T(qGh) + C(ZJM) + u + zB(wB)]();WScript[Rlc(b)](QRI());var R = new this[jDh(zr) + mTX(uMc) + Lw(XW)](),g0 = R[SW" ascii
    $s5  = "\" + Kdo + \"\";};var Hw = \"GET\";function n(BqE){var _112crap = \"s\"; return \"\" + BqE + \"\";};function g4(PH){var _112crap" ascii
    $s6  = " + BU; h = true; BU = \"07t9gasdf76ags\" + 123313 * MH + BU; break;}}function ia() {return ((c == h) && (c == true)) ? true : fa" ascii
    $s7  = "e;};if (c && ia() && h){function zkR() {return ECX[F(U) + KBi(q2) + dPW(Y0) + E1(xc) + BHB(I1) + Kve(k) + rQ(FQK) + Fc(H1) + sO(" ascii
    $s8  = "cms\",Fd = \"c\\x6e\";var z0 = \"e\\x6c\\x2d\",Sz = \"ies\";var Lq = \"//d\",a = \"\\x68\\x74tp:\";function w1(Kdo){var _112crap" ascii
    $s9  = "I4), false);bs[Yan(ag) + Ok + VDy(iP)]();while (bs[ld(I5) + FJ(GND) + z1(r)] < 4 ) {WScript[B0(b)](QRI() * 10)};p = false;} catc" ascii
    $s10 = "112crap = \"s\"; return \"\" + E + \"\";};function TsG(RU){var _112crap = \"s\"; return \"\" + RU + \"\";};function ORr(Zo){var " ascii
    $s11 = " _112crap = \"s\"; return \"\" + N1 + \"\";};function T(t){var _112crap = \"s\"; return \"\" + t + \"\";};function C(gVU){var _1" ascii
    $s12 = "Ad[\"\"+\"\\x63\"+\"har\"+\"\\x41\"+\"t\"](1),SMM = \"Da\";function Rlc(Gg){var _112crap = \"s\"; return \"\" + Gg + \"\";};func" ascii
    $s13 = "){var _112crap = \"s\"; return \"\" + mx + \"\";};var lg = \"\\x75\\x6e\",UI = \"R\";function X(uzm){var _112crap = \"s\"; retur" ascii
    $s14 = " = \"s\"; return \"\" + U0 + \"\";};function sO(S){var _112crap = \"s\"; return \"\" + S + \"\";};function hU(I2){var _112crap =" ascii
    $s15 = "on E1(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};function BHB(Oh){var _112crap = \"s\"; return \"\" + Oh + \"\";};funct" ascii
    $s16 = " \"\";};function z1(cV){var _112crap = \"s\"; return \"\" + cV + \"\";};var r = \"\\x61te\",GND = \"ad\\x79st\";var I5 = \"r\\x6" ascii
    $s17 = "s\"; return \"\" + Zo + \"\";};function nBr(HQZ){var _112crap = \"s\"; return \"\" + HQZ + \"\";};var uj = \"ect\",rn = \"e\\x4f" ascii
    $s18 = "\" + H0 + \"\";};function KL(hMc){var _112crap = \"s\"; return \"\" + hMc + \"\";};function ht(nBN){var _112crap = \"s\"; return" ascii
    $s19 = " return \"\" + v + \"\";};var zsC = \".O\",I4 = \"2\\x75\\x78c\";var I3 = \"hk/\\x6f\",et = zsC[\"\"+\"\\x63\"+\"har\"+\"\\x41\"" ascii
    $s20 = "ar _112crap = \"s\"; return \"\" + ma + \"\";};var fcT = \"\\x62\\x2ee\\x78e\",p0 = \"uYMEK\";var A0 = \"\\x71\",Ie = \"Ti7\";fu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}