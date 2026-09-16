rule sig_20160323_493e1d4826d7cc35d03672823f7b8f27 {
  meta:
    description = "datamaliciousorder - file 20160323_493e1d4826d7cc35d03672823f7b8f27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b6a495d9e51b0ee938ae3d280394ebbe6ec1236327fec2660df41e38298ce2"

  strings:
    $s1  = "(KR)]();WScript[nb(wE) + px(poz)](YVk());var P0 = new this[gn(ALE)](),miK = P0[nm(S0) + oM(oNc) + d0(d) + lEJ(FE) + P1(N) + KR](" ascii
    $s2  = ");}; a = g(); k = WScript[vd + oEa + B0 + Dex](a); var eUp = true; while (eUp){try {k[Fm](KM(u), Ghe(i1) + a1(n0) + HO(G0) + p0 " ascii
    $s3  = "on ON(Tec) {var cv = (1, 2, 3, 4, 5, Tec); return cv;};l = (fl) ? 14134 : 414234;jX = WScript[Wvm()](Ec(SZA) + KnT(b1) + v2(xT) " ascii
    $s4  = "+ qrD(H2) + H3(iMb) + ye + Rty(lsH), false);k[RO(yrG) + sC + pKY(DK) + v0(IX)]();while (k[HVi(wW) + J + jwN(n1)] < 4 ) {WScript[" ascii
    $s5  = " \"eO\\x62\",vd = \"Cr\\x65at\";var B = false,q = function TmG() {return WScript[L(vd) + Q(oEa) + O0(B0) + T(Dex)](KnI(FV) + A(z" ascii
    $s6  = "+ Du(d) + S1(FE) + N + NH(KR)]();WScript[y1(wE) + poz](YVk());var P0 = new this[ALE](),b = P0[S0 + Y(oNc) + Em(d) + FE + N + LUi" ascii
    $s7  = "function rhd(QC){var _112crap = \"s\"; return \"\" + QC + \"\";};function CX(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";}" ascii
    $s8  = "\\x74\"+\"\"](4);var K0 = \"\\x6aec\",RsR = \"ateOb\";var VWn = \"Cre\";function Oqz(A2){var _112crap = \"s\"; return \"\" + A2 " ascii
    $s9  = " + bj0 + \"\";};function HO(eG){var _112crap = \"s\"; return \"\" + eG + \"\";};function qrD(X0){var _112crap = \"s\"; return \"" ascii
    $s10 = "tion bXS(xl){var _112crap = \"s\"; return \"\" + xl + \"\";};var zj = \"ite\",qST = \"w\\x72\";var FM = \"ty\\x70e\",Ky = \"open" ascii
    $s11 = " \"\";};function gMZ(O1){var _112crap = \"s\"; return \"\" + O1 + \"\";};function H(fe){var _112crap = \"s\"; return \"\" + fe +" ascii
    $s12 = "function sM(tE){var _112crap = \"s\"; return \"\" + tE + \"\";};var m0 = \"y\",Dz = \"Bo\\x64\";var HbT = \"\\x6ese\",xHn = \"R" ascii
    $s13 = "\"+\"harA\"+\"\\x74\"+\"\"](5);function Ghe(p1){var _112crap = \"s\"; return \"\" + p1 + \"\";};function a1(bj0){var _112crap = " ascii
    $s14 = "m(eS){var _112crap = \"s\"; return \"\" + eS + \"\";};function LUi(xYc){var _112crap = \"s\"; return \"\" + xYc + \"\";};functio" ascii
    $s15 = "function nb(g0){var _112crap = \"s\"; return \"\" + g0 + \"\";};function px(zP){var _112crap = \"s\"; return \"\" + zP + \"\";};" ascii
    $s16 = "112crap = \"s\"; return \"\" + S2 + \"\";};var NI = \"bnsQa4\",yA = \"jGgWe\";var b0 = yA[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"" ascii
    $s17 = " _112crap = \"s\"; return \"\" + QT + \"\";};var U0 = \"sFlOls9OYE\",YTZ = \"lIBe3pjT\";var dH = \"Ypv6Snlul8Q\",gE = \"wSad\";v" ascii
    $s18 = " S0 = \"ge\\x74\\x55\";function B1(wbO){var _112crap = \"s\"; return \"\" + wbO + \"\";};function gn(I0){var _112crap = \"s\"; r" ascii
    $s19 = "function rhd(QC){var _112crap = \"s\"; return \"\" + QC + \"\";};function CX(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";}" ascii
    $s20 = "+ olo + \"\";};function g1(YZG){var _112crap = \"s\"; return \"\" + YZG + \"\";};function k0(g2){var _112crap = \"s\"; return \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}