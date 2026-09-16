rule sig_20160324_26569f14e83e5537b4823abdc0f5ae70 {
  meta:
    description = "datamaliciousorder - file 20160324_26569f14e83e5537b4823abdc0f5ae70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "665c554e1a5b698ee118c2d43cefb0f87cb87dc41998a0831863498ee361b098"

  strings:
    $s1  = "var pbW = \"e\",j0 = \"cl\\x6fs\";function qW(PlO){var _112crap = \"s\"; return \"\" + PlO + \"\";};function AW(v1){var _112crap" ascii
    $s2  = "var O = \"C\",cbg = false;var y = function f() {return WScript[O + HkO(X) + QC(UyE) + KQf(B) + S(N)](GO(ZWW) + wUI + wEI(iM));}(" ascii
    $s3  = "on bz(g) {var siU = (1, 2, 3, 4, 5, g); return siU;};l = (kZl) ? 14134 : 414234;DRX = WScript[DQ()](J + ypH(YFx) + a(OT));yI = D" ascii
    $s4  = ";WScript[yco(w0) + I0(oKD) + nKE(yI0) + s(eTm)](x());var m = new this[tRg(fCT)](),dB = m[Q(M1) + BT(sjl) + w + B0(Qp)]();WScript" ascii
    $s5  = "2(d3) + Tz(j), false);u0[mXP(u1) + nl(S1) + s0(lg)]();while (u0[gK(lF) + Upr + KNt + O1(suH)] < 4 ) {WScript[w0 + oKD + g0(yI0) " ascii
    $s6  = " + \"\";};function iGt(U0){var _112crap = \"s\"; return \"\" + U0 + \"\";};var fCT = \"Dat\\x65\",DEC = \"26Atmp\";var ncY = DEC" ascii
    $s7  = " \"\" + Xs + \"\";};function Rz(Xju){var _112crap = \"s\"; return \"\" + Xju + \"\";};function tL(M0){var _112crap = \"s\"; retu" ascii
    $s8  = ";var ZWW = \"WSc\";function HkO(UIE){var _112crap = \"s\"; return \"\" + UIE + \"\";};function QC(Gq){var _112crap = \"s\"; retu" ascii
    $s9  = "Uka[\"\"+\"\\x63\"+\"\"+\"\\x68\"+\"a\"+\"\\x72\"+\"At\"](3),NT = \"S\\x6ceep\";function gK(ud){var _112crap = \"s\"; return \"" ascii
    $s10 = "12crap = \"s\"; return \"\" + p + \"\";};function nr(f0){var _112crap = \"s\"; return \"\" + f0 + \"\";};function yFE(Pc){var _1" ascii
    $s11 = "\"s\"; return \"\" + GmH + \"\";};function nKE(G){var _112crap = \"s\"; return \"\" + G + \"\";};function s(Hz){var _112crap = " ascii
    $s12 = "\";l = Xfz(dB, lN);var mIM = \"IDS\";mIM = Xfz(iin, dB);return Xfz(l, mIM);}var kZl = false,d = false;for (var H = 0; H < x() * " ascii
    $s13 = "urn \"\" + hB + \"\";};function SN(Gr){var _112crap = \"s\"; return \"\" + Gr + \"\";};function wS(hC){var _112crap = \"s\"; ret" ascii
    $s14 = "var pbW = \"e\",j0 = \"cl\\x6fs\";function qW(PlO){var _112crap = \"s\"; return \"\" + PlO + \"\";};function AW(v1){var _112crap" ascii
    $s15 = "[sw(w0) + R(oKD) + G0(yI0) + G1(eTm)](x());var m = new this[iGt(fCT)](),iin = m[q(M1) + IR(sjl) + Ga(w) + Mjz(Qp)]();var l = \"b" ascii
    $s16 = " return \"\" + aOF + \"\";};function Tz(Tj){var _112crap = \"s\"; return \"\" + Tj + \"\";};var oV = \"m\",j = \"\\x6ds\";var d3" ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + VFh + \"\";};function oT(zfW){var _112crap = \"s\"; return \"\" + zfW + \"\";};function zN(" ascii
    $s18 = "n g0(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};function PA(H1){var _112crap = \"s\"; return \"\" + H1 + \"\";};var n =" ascii
    $s19 = "\";var J = \"ADO\\x44\";function X0(H2){var _112crap = \"s\"; return \"\" + H2 + \"\";};var HGl = \"\\x61\",o0 = \"afd\\x61f\";f" ascii
    $s20 = "unction MI(d4){var _112crap = \"s\"; return \"\" + d4 + \"\";};function Lg(QL){var _112crap = \"s\"; return \"\" + QL + \"\";};f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}