rule sig_20160323_a67713b3f9a649f42ad056fb402ff9c4 {
  meta:
    description = "datamaliciousorder - file 20160323_a67713b3f9a649f42ad056fb402ff9c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64e1376ea77382b83f63e47b9ed3e2b632676262c6a9f717c808a9cb97e15452"

  strings:
    $s1  = "+ Mn(b2) + DW(aX), true);};}function Z(W) {var cjY = (1, 2, 3, 4, 5, W); return cjY;};e = (HmP) ? 14134 : 414234;g = WScript[JP(" ascii
    $s2  = " vi(Ckg) + y + j0(T0)]();WScript[K(S) + XNU(sAT)](bR());var P = new this[nOF(n)](),ak = P[KYB(llm) + y0(H) + Nm(CX) + CO(Ckg) + " ascii
    $s3  = "ItR(y) + T0]();WScript[G2(S) + sAT](bR());var P = new this[qL(n)](),mp = P[mWY(llm) + P0(H) + CX + Ckg + XSb(y) + N(T0)]();var e" ascii
    $s4  = "\\x6a\";var DMP = \"Cr\\x65\\x61t\",T = false;var o0 = function p() {return WScript[DMP + ZJ(r) + e0(XCA)](TWx + CXO(I) + Pq(r0)" ascii
    $s5  = "(BgK) + D + BM] < 4 ) {WScript[gh(S) + U0(sAT)](bR() * 10)};vVl = false;} catch(GG){vVl = (z0(qi), r3(hE) + nO + G4(u2), vr(z1) " ascii
    $s6  = " = WScript[DMP + Wu(r) + G0(XCA)](IgB); var vVl = true; while (vVl){try {j[v0(K0) + Od(d) + fe(zfj)](Gn(omB) + FH, C2(TqX) + hb " ascii
    $s7  = "function pwK(Fc){var _112crap = \"s\"; return \"\" + Fc + \"\";};var hl = \"clos\\x65\";function bsw(zx){var _112crap = \"s\"; r" ascii
    $s8  = "\\x66as\\x64\",hE = \"f\\x61\";function z0(Nq){var _112crap = \"s\"; return \"\" + Nq + \"\";};var qi = \"as\\x64\\x66a\",Gb = " ascii
    $s9  = "\\x74\";function TJN(ab){var _112crap = \"s\"; return \"\" + ab + \"\";};function hA(v1){var _112crap = \"s\"; return \"\" + v1 " ascii
    $s10 = "ion HUj(ngp){var _112crap = \"s\"; return \"\" + ngp + \"\";};function y2(C4){var _112crap = \"s\"; return \"\" + C4 + \"\";};va" ascii
    $s11 = "har\"+\"\\x41\"+\"t\"](0),YSg = \"re\";function F1(V){var _112crap = \"s\"; return \"\" + V + \"\";};var StM = \"nd\",u1 = \"s" ascii
    $s12 = " hb = \"\\x2f/ev\\x61\",TqX = \"htt\\x70:\";function Gn(H1){var _112crap = \"s\"; return \"\" + H1 + \"\";};var FH = \"\\x54\",o" ascii
    $s13 = " = \"Sle\";function ugW(W2){var _112crap = \"s\"; return \"\" + W2 + \"\";};function PV(kWJ){var _112crap = \"s\"; return \"\" +" ascii
    $s14 = "TPt(bf){var _112crap = \"s\"; return \"\" + bf + \"\";};function MKi(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};functio" ascii
    $s15 = " \"s\"; return \"\" + l + \"\";};var XG = \"Ofm6llxU\",suG = XG[\"char\"+\"\\x41\"+\"t\"](4);var r0 = \".\\x53he\\x6c\",I = \"ip" ascii
    $s16 = "ap = \"s\"; return \"\" + ZnN + \"\";};function n0(BDN){var _112crap = \"s\"; return \"\" + BDN + \"\";};var WDM = \"\\x50\\x25/" ascii
    $s17 = "function pwK(Fc){var _112crap = \"s\"; return \"\" + Fc + \"\";};var hl = \"clos\\x65\";function bsw(zx){var _112crap = \"s\"; r" ascii
    $s18 = "+ \"\";};function G2(YE){var _112crap = \"s\"; return \"\" + YE + \"\";};function gh(jf){var _112crap = \"s\"; return \"\" + jf " ascii
    $s19 = "+ OYa(yj) + ann + TM(S0) + fm(duN) + fs(zh) + zhE(B0) + SF(rX) + U3(z), false);j[u1 + F1(StM)]();while (j[ugW(YSg) + PV(sD) + G3" ascii
    $s20 = "/if (T){function bR(){return 22;};var e = 0,C0 = 0;function QWK(){var P = new this[Zn(n)](),HZI = P[TPt(llm) + MKi(H) + uA(CX) +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}