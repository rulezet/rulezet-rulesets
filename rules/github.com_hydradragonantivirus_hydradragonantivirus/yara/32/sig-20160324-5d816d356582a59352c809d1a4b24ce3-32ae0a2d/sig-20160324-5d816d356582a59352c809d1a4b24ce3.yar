rule sig_20160324_5d816d356582a59352c809d1a4b24ce3 {
  meta:
    description = "datamaliciousorder - file 20160324_5d816d356582a59352c809d1a4b24ce3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94420f8eb0d24bfcafcbef1349af7765f7feff2750e81829dd1b40cffda008fe"

  strings:
    $s1  = "function cmf(a1){var _112crap = \"s\"; return \"\" + a1 + \"\";};var M1 = \"\\x65\",SRH = \"cl\\x6f\\x73\";function H(ddy){var _" ascii
    $s2  = "P;}; chP = aif(); LjG = WScript[gTQ](chP); var l = 1; while (l){try {LjG[iZ](Y0, Tm + n2 + X0 + SZM + F0 + J0 + KS(KY) + Nc, fal" ascii
    $s3  = "T0) + Z + cL(x0)]();WScript[e(WS)](hYX());var eqC = new this[mSG(EZC)](),v = eqC[aSW + iM(T0) + Z + x0]();WScript[WS](hYX());var" ascii
    $s4  = "Z, 2);};}function R(a) {var z0 = (1, 2, 3, 4, 5, a); return z0;};OeP = WScript[NHC()](HG(wmJ) + a0 + haV);chP = OeP;chP[(iZ)]();" ascii
    $s5  = "p = \"s\"; return \"\" + IuH + \"\";};var x0 = \"o\\x6eds\",Z = \"li\\x73ec\";var T0 = \"\\x43M\\x69l\",aSW = \"get\\x55T\";func" ascii
    $s6  = ") ? 1 : cNi;};if (QA && dc() && n){function LCs() {return m[n1 + EeZ + Uvc + y + EI + QC](qQ + Y) + bz(S) + Nvf + Wp(KuH) + X + " ascii
    $s7  = "23313 * cX + GSK; n = true; GSK = \"07t9gasdf76ags\" + 123313 * cX + GSK; break;}}function dc() {return ((QA == true) && (QA == " ascii
    $s8  = "se);LjG[Z0]();F = \"Sleep\";while (LjG[oSI(V0) + flu] < 4 ) {WScript[F](hYX() * 10)};l = cNi;} catch(w){l = (c + GJ, I + K, dl +" ascii
    $s9  = "BcW = \"\\x65\\x4fb\\x6ae\",h = \"C\\x72\\x65at\";var d = false,gTQ = \"CreateObject\";var m = function tHt() {return WScript[gT" ascii
    $s10 = " eqC = new this[EZC](),KEo = eqC[VB(aSW) + T0 + Z + x0]();var cX = \"WMp\";cX = Dw(v, p);var GSK = \"dzA\";GSK = Dw(KEo, v);retu" ascii
    $s11 = "e + \"\";};function Wp(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};var P = \"\\x78e\",X = \"gQ\\x2ee\";var KuH = \"x\\x5" ascii
    $s12 = ";var CJB = \"tio\\x6e\",KAR = \"po\\x73\\x69\";function wu(XYa){var _112crap = \"s\"; return \"\" + XYa + \"\";};var d0 = \"o\\x" ascii
    $s13 = "w(cX, GSK);}var QA = false,n = false;for (var z = cNi; z < hYX() * 1; z++){if (b() != cNi){QA = true; GSK = \"07t9gasdf76ags\" +" ascii
    $s14 = "var pH = \"\\x48T\\x54P\",Zk = \"2.X\\x4dL\";var AXJ = \"MSXM\\x4c\";function Dre(MZ){var _112crap = \"s\"; return \"\" + MZ + " ascii
    $s15 = "(Qq){var _112crap = \"s\"; return \"\" + Qq + \"\";};var Oi = \"\\x53h\\x65l\\x6c\",Dfi = \"ip\\x74\\x2e\";var s = \"W\\x53cr\"," ascii
    $s16 = "ue;  @end@*/if (d){function hYX(){return 22;};var cX = 0,GSK = 0;function b(){var eqC = new this[T(EZC)](),p = eqC[zUw(aSW) + C(" ascii
    $s17 = "rap = \"s\"; return \"\" + W + \"\";};function mSG(jgC){var _112crap = \"s\"; return \"\" + jgC + \"\";};var EZC = \"Dat\\x65\"," ascii
    $s18 = "nction zUw(J){var _112crap = \"s\"; return \"\" + J + \"\";};function C(jV){var _112crap = \"s\"; return \"\" + jV + \"\";};func" ascii
    $s19 = "= \"CMil\\x6c\",Q = \"\\x67etUT\";var u = \"D\\x61\\x74e\";function e(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};var WS" ascii
    $s20 = "var _112crap = \"s\"; return \"\" + Sl + \"\";};function iM(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};function VB(IuH)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}