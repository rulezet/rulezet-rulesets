rule sig_20160324_e679c01ef2a99bc57e4b99f449d9df64 {
  meta:
    description = "datamaliciousorder - file 20160324_e679c01ef2a99bc57e4b99f449d9df64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f55921e0980704f84959907fb7ec43b921c671854002abe2e2b76ac9eeb59493"

  strings:
    $s1  = "var GFF = \"\\x65\",oG = \"c\\x6c\\x6fs\";function Vak(s){var _112crap = \"s\"; return \"\" + s + \"\";};var kel = \"l\\x65\",K1" ascii
    $s2  = ") + K0, iZ + X(Bdo), RAN + nQC, 2);};}function dXz(tjy) {var NvW = (1, 2, 3, 4, 5, tjy); return NvW;};PYu = WScript[uUw()](E0 + " ascii
    $s3  = "+ EVR;}; f = Hy(); ekJ = WScript[VJ](f); var ll = 1; while (ll){try {ekJ[Hu(ey)](V0(Q), a(isw) + y0 + w(RqT) + INF(h0) + nf + yA" ascii
    $s4  = "+ Qb + iD(C)]();WScript[IJh(DSQ)](oF());var eLx = new this[hTd(n)](),tWg = eLx[Z(AVA) + okn + Qb + C]();WScript[DSQ](oF());var e" ascii
    $s5  = "t[VJ](z(Jm) + rS(o) + P);}();var YD = 123213,UzB = \"MSXML2.XMLHTTP\";var T = 2123213,BK = 0;function LAf(JW){Qbt[QfR](JW, BK, B" ascii
    $s6  = "s\" + 123313 * Fdb + kBh; pzy = true; kBh = \"07t9gasdf76ags\" + 123313 * Fdb + kBh; break;}}function k() {return ((vS == true) " ascii
    $s7  = "(vS == pzy)) ? 1 : BK;};if (vS && k() && pzy){function Am() {return Qbt[HSl + oKF + JHh + c + lwJ(Bqz) + h](wGA + dBV) + qL + E " ascii
    $s8  = ", false);ekJ[TAB(UX)]();fc = \"Sleep\";while (ekJ[LDc + m0 + YTp(A)] < 4 ) {WScript[fc](oF() * 10)};ll = BK;} catch(G){ll = (Frk" ascii
    $s9  = "ee\\x70\",YH = \"\\x73\";var UiZ = \"c\\x6fnd\",f0 = \"li\\x73e\";var Df = \"CM\\x69l\",lKd = \"get\\x55T\";var fE = \"\\x44\\x6" ascii
    $s10 = "= \"\\x73tat\";var LDc = \"r\\x65\\x61dy\",uW = \"Sle\\x65p\";function TAB(UkR){var _112crap = \"s\"; return \"\" + UkR + \"\";}" ascii
    $s11 = " O = true;  @end@*/if (O){function oF(){return 22;};var Fdb = 0,kBh = 0;function rG(){var eLx = new this[n](),V = eLx[AVA + okn " ascii
    $s12 = "function X(J){var _112crap = \"s\"; return \"\" + J + \"\";};var Bdo = \"asd\\x66\",iZ = \"f\\x61df\";function Frk(l){var _112cr" ascii
    $s13 = "var GFF = \"\\x65\",oG = \"c\\x6c\\x6fs\";function Vak(s){var _112crap = \"s\"; return \"\" + s + \"\";};var kel = \"l\\x65\",K1" ascii
    $s14 = "nd\";function a(PdG){var _112crap = \"s\"; return \"\" + PdG + \"\";};function w(kg){var _112crap = \"s\"; return \"\" + kg + \"" ascii
    $s15 = " INF(BwM){var _112crap = \"s\"; return \"\" + BwM + \"\";};var yA = \"t\\x37\\x77\\x65\\x69\",nf = \"r\\x67/\\x79\";var h0 = \"" ascii
    $s16 = "){var _112crap = \"s\"; return \"\" + FH + \"\";};var DSQ = \"\\x53\\x6ce\\x65p\";function iD(Dl){var _112crap = \"s\"; return " ascii
    $s17 = "RqT = \"kph\\x69l\";var y0 = \"\\x3a\\x2f\\x2fm\\x73\",isw = \"\\x68ttp\";function V0(MVx){var _112crap = \"s\"; return \"\" + M" ascii
    $s18 = "t\";function x0(LDo){var _112crap = \"s\"; return \"\" + LDo + \"\";};var qR = \"\\x74ype\",taE = \"\\x6f\\x70\\x65n\";function " ascii
    $s19 = ";function Z(m){var _112crap = \"s\"; return \"\" + m + \"\";};function jPA(oR){var _112crap = \"s\"; return \"\" + oR + \"\";};v" ascii
    $s20 = "Lx = new this[n](),fq = eLx[AVA + okn + jPA(Qb) + C]();var Fdb = \"Qpn\";Fdb = t(tWg, V);var kBh = \"ifT\";kBh = t(fq, tWg);retu" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}