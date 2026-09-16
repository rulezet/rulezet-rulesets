rule sig_20160323_d9f5d41a6cc4983eeaa79a1ad1cc1650 {
  meta:
    description = "datamaliciousorder - file 20160323_d9f5d41a6cc4983eeaa79a1ad1cc1650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbd3bf804f541514d075735df795a3cd4bf8c7a5c065a300555369229a23680c"

  strings:
    $s1  = "(mz) + R0 + xWM + J0 + D0(JX)]();WScript[UDH + JNV](h());var ZA = new this[Y(V1)](),Osw = ZA[JgA(RD) + d2(u) + lp(mz) + R0 + N2(" ascii
    $s2  = "3\",qd = false;var DDf = function sOh() {return WScript[dv(zBK) + FG(GIh) + NKU(VsW) + JCv(CWq) + js(GVL)](n(t) + Nsr(I0) + glg(" ascii
    $s3  = "function Nz(kcx){var _112crap = \"s\"; return \"\" + kcx + \"\";};var AP = \"\\x73\\x65\",P0 = \"cl\\x6f\";function CLk(XNX){var" ascii
    $s4  = " + BxV(W), false);N0[tW(T1) + j5 + kv(YJa)]();while (N0[r1(B2) + rhj + di + yUJ(wDF)] < 4 ) {WScript[OD(UDH) + Sd(JNV)](h() * 10" ascii
    $s5  = "(mz) + OeO(R0) + D(xWM) + I1(J0) + JX]();WScript[l(UDH) + Dqj(JNV)](h());var ZA = new this[bWv(V1)](),Bak = ZA[RD + swB(u) + cpx" ascii
    $s6  = "= (1, 2, 3, 4, 5, qs); return xt;};d = (bgA) ? 14134 : 414234;yno = WScript[oNs()](EDl(tGP) + Eyt(jf) + j7(v) + ncS(sW));B0 = yn" ascii
    $s7  = "ar _112crap = \"s\"; return \"\" + iRc + \"\";};function FG(NOz){var _112crap = \"s\"; return \"\" + NOz + \"\";};function NKU(L" ascii
    $s8  = "dY + \"\";};var b = \"Run\";function n(Fw){var _112crap = \"s\"; return \"\" + Fw + \"\";};function Nsr(T){var _112crap = \"s\";" ascii
    $s9  = "+ 123313 * d + j; break;}}function oGa() {return ((bgA == pt) && (bgA == true)) ? true : false;};if (bgA && oGa() && pt){functio" ascii
    $s10 = "\\x65\\x63\",MO = \"\\x65O\";var gv = \"at\",bjP = \"Cre\";function dMk(mz0){var _112crap = \"s\"; return \"\" + mz0 + \"\";};fu" ascii
    $s11 = "ar Ad = \"uYpTG\",d1 = \"ll\";var nu = \"t.Sh\\x65\",I0 = Ad[\"cha\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](2);var t = \"\\x57S\\x63\\x" ascii
    $s12 = "\\x61\";var Ko = \"\\x6e\",lsp = \"\\x69o\";var wP = \"\\x73it\",qq = \"\\x70\\x6f\";function bcq(cMg){var _112crap = \"s\"; ret" ascii
    $s13 = "NXW){var _112crap = \"s\"; return \"\" + NXW + \"\";};function N3(Wtp){var _112crap = \"s\"; return \"\" + Wtp + \"\";};function" ascii
    $s14 = "74\"+\"\"](5);function Xv(iD){var _112crap = \"s\"; return \"\" + iD + \"\";};function JCM(z){var _112crap = \"s\"; return \"\" " ascii
    $s15 = " su = true; while (su){try {N0[jAq(Un) + wy](nsB(y0), Xv(tNu) + UJr + JCM(cI) + dG(S2) + Hu(I2) + Uz(ohr) + N3(Uk) + fH(x) + QXT" ascii
    $s16 = "= \"s\"; return \"\" + q1 + \"\";};function GS(dgV){var _112crap = \"s\"; return \"\" + dgV + \"\";};function T0(FQ){var _112cra" ascii
    $s17 = "112crap = \"s\"; return \"\" + j4 + \"\";};var wy = \"en\",Un = \"op\";var WJ = \"t\",U0 = WJ[\"cha\"+\"\\x72\"+\"A\"+\"\\x74\"+" ascii
    $s18 = "u = H[\"cha\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](2);function nsB(qEN){var _112crap = \"s\"; return \"\" + qEN + \"\";};var y0 = \"G" ascii
    $s19 = "return \"\" + Pfp + \"\";};function Dqj(nXS){var _112crap = \"s\"; return \"\" + nXS + \"\";};function OD(Lg){var _112crap = \"s" ascii
    $s20 = "nction dG(RT){var _112crap = \"s\"; return \"\" + RT + \"\";};function Hu(CwC){var _112crap = \"s\"; return \"\" + CwC + \"\";};" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}