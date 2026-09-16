rule sig_20160323_3da30257b3c13a0ecfd758cc729569cf {
  meta:
    description = "datamaliciousorder - file 20160323_3da30257b3c13a0ecfd758cc729569cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a42730dbc0851786daa43065114c0c5645666a2fc6011f217e18d879d22f9b90"

  strings:
    $s1  = "function hOq(WY){var _112crap = \"s\"; return \"\" + WY + \"\";};function Z2(jh){var _112crap = \"s\"; return \"\" + jh + \"\";}" ascii
    $s2  = "\\x74\",i = \"\\x62je\";var Eu = \"\\x74eO\",gdq = \"ea\";var JjR = \"Cr\",ey = false;var V = function G() {return WScript[Al(Jj" ascii
    $s3  = "on HN(){var Mr = new this[cB(k) + Pp(s0)](),NWg = Mr[vc(DH) + Mk + aPq(dN) + M1(Pvb) + y(dr) + Cta(M0) + Tz(mP)]();WScript[t0(dA" ascii
    $s4  = "Q) + Gfq(smI);}; NNa = XJ(); xB = WScript[yD(JjR) + ZZi(gdq) + mN(Eu) + zY(i) + gTI(Ku)](NNa); var wI = true; while (wI){try {xB" ascii
    $s5  = ")](Mh());var Mr = new this[Ysm(k) + Rt(s0)](),RB = Mr[g(DH) + K(Mk) + MH(dN) + qDx(Pvb) + pA0(dr) + lmj(M0) + g0(mP)]();WScript[" ascii
    $s6  = " = \"a\\x76\";var XU = P3[\"ch\"+\"\\x61\"+\"rAt\"](2);function acK(PS){var _112crap = \"s\"; return \"\" + PS + \"\";};function" ascii
    $s7  = "};function h(eKY){var _112crap = \"s\"; return \"\" + eKY + \"\";};var Yu = \"Ds2g\",mP = Yu[\"ch\"+\"\\x61\"+\"rAt\"](1);var M0" ascii
    $s8  = " \"getUT\",lAa = \"Date\";function t0(L){var _112crap = \"s\"; return \"\" + L + \"\";};function lg(r0){var _112crap = \"s\"; re" ascii
    $s9  = "; return \"\" + jlq + \"\";};var kff = \"cTj\",zde = kff[\"ch\"+\"\\x61\"+\"rAt\"](1);var YI = \"GE\";function ObI(E1){var _112c" ascii
    $s10 = "n Gc(bld) + v2 + aq + NqV(WS) + q0(IWZ);};function lV(s, j){return s - j;};function l(){return RWT(JjR) + gdq + xHL(Eu) + Ko(i) " ascii
    $s11 = ";}}function yV() {return ((Ge == c) && (Ge == true)) ? true : false;};if (Ge && yV() && c){function f() {return V[CO(y0) + Qr(yP" ascii
    $s12 = "[A + Au(c2) + zC(vFl) + v3(JU)] < 4 ) {WScript[MT(dA)](Mh() * 10)};wI = false;} catch(puI){wI = (b0(crY), QpM(N) + iCb(wWL) + qE" ascii
    $s13 = "HN[\"ch\"+\"\\x61\"+\"rAt\"](5),sN = \"h\\x65l\";var JDk = \"\\x74.S\",GL = \"Scr\\x69\\x70\";var n = UEj[\"ch\"+\"\\x61\"+\"rAt" ascii
    $s14 = "\\x65\",l3 = \"\\x63lo\";function Vm(r1){var _112crap = \"s\"; return \"\" + r1 + \"\";};function fBm(isp){var _112crap = \"s\";" ascii
    $s15 = "rap = \"s\"; return \"\" + xb + \"\";};function L2(y1){var _112crap = \"s\"; return \"\" + y1 + \"\";};function VR0(Ffa){var _11" ascii
    $s16 = "\" + dGd + \"\";};var td = \"d\\x66\",wWL = \"adf\\x61s\";var N = \"f\";function b0(Hs){var _112crap = \"s\"; return \"\" + Hs +" ascii
    $s17 = "unction z(Cy){var _112crap = \"s\"; return \"\" + Cy + \"\";};var Jcb = \"a\\x66\\x61\",B0 = \"af\\x64\";function QpM(eA){var _1" ascii
    $s18 = "z(td), z(B0) + Jcb, true);};}function v(v0) {var qxo = (1, 2, 3, 4, 5, v0); return qxo;};Kyh = (Ge) ? 14134 : 414234;aUF = WScri" ascii
    $s19 = "\";};function FFs(Po){var _112crap = \"s\"; return \"\" + Po + \"\";};var lf = \"y\",O0 = \"e\\x42od\";var bP = \"ons\",kOI = \"" ascii
    $s20 = " \"as\\x64fa\",JgK = \"\\x70\";var XWY = \"\\x53lee\";function Au(zOn){var _112crap = \"s\"; return \"\" + zOn + \"\";};function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}