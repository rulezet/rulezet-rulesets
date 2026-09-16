rule sig_20160324_6b2052aac2abd5498a113ad0cc9b7c94 {
  meta:
    description = "datamaliciousorder - file 20160324_6b2052aac2abd5498a113ad0cc9b7c94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a4ad580ad07c0c28c94ac8d0fbb7055f45944c3cfe767e4854a75b1fdd3bda"

  strings:
    $s1  = "var V2 = \"\\x65\",c0 = \"c\\x6cos\";function Q0(AhS){var _112crap = \"s\"; return \"\" + AhS + \"\";};var BR = \"\\x6c\\x65\",X" ascii
    $s2  = " \"\" + VRf + \"\";};function RYP(DJi){var _112crap = \"s\"; return \"\" + DJi + \"\";};var p0 = \"b5\\x75\\x61s\",GIs = \".com" ascii
    $s3  = "Y + Li + lUV + CT]();WScript[bYR](jI());var cWA = new this[aWe](),Py = cWA[VO(uSY) + Li + p(lUV) + CT]();WScript[bYR](jI());var " ascii
    $s4  = "E) + FOA(IbV), v + kq(ga), 2);};}function nvD(J) {var s = (1, 2, 3, 4, 5, J); return s;};V = WScript[UyM()](U1 + FyG + ED);c = V" ascii
    $s5  = "; c = UL(); ugn = WScript[m](c); var yU = 1; while (yU){try {ugn[Gx](PJ, g + FoE(ElX) + u0(Ch) + if0 + Mc(GIs) + RYP(p0), false)" ascii
    $s6  = ");};function UL(){return x;};function Rx(sgr, Us){return sgr - Us;};function UyM(){return m;};/*@cc_on  @if (@_win32 || @_win64)" ascii
    $s7  = "pt[m](OmG + yXL(hi) + of(Rl));}();var Zm = 123213,x = \"MSXML2.XMLHTTP\";var U = 2123213,Of = 0;function VIS(kK){zq[KA](kK, Of, " ascii
    $s8  = "1 : Of;};if (rO && FlT() && oze){function K() {return zq[l0 + hl + EoE + MI(WLe) + znU + Cp](La(nC) + ZA) + AX + cl + Aq + xrp;}" ascii
    $s9  = "13 * Gz + r; oze = true; r = \"07t9gasdf76ags\" + 123313 * Gz + r; break;}}function FlT() {return ((rO == true) && (rO == oze)) " ascii
    $s10 = ";ugn[Hs(ATP)]();A = \"Sleep\";while (ugn[y0 + wx(V1) + F] < 4 ) {WScript[A](jI() * 10)};yU = Of;} catch(WZ){yU = (krp + Lm, sjC(" ascii
    $s11 = "43.e\";var cl = \"9\\x57l\\x54z\",AX = \"1L\\x37c\";function La(n){var _112crap = \"s\"; return \"\" + n + \"\";};var ZA = \"\\x" ascii
    $s12 = "OA(t0){var _112crap = \"s\"; return \"\" + t0 + \"\";};var IbV = \"asd\\x66\",GcE = \"\\x66a\\x64f\";var Lm = \"\\x61\",krp = \"" ascii
    $s13 = " wx(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};var F = \"\\x65\",V1 = \"\\x73\\x74at\";var y0 = \"rea\\x64\\x79\",kGA =" ascii
    $s14 = "rn \"\" + bEw + \"\";};function of(zdO){var _112crap = \"s\"; return \"\" + zdO + \"\";};var Rl = \"e\\x6c\\x6c\",hi = \"pt.\\x5" ascii
    $s15 = "x(Gz, r);}var rO = false,oze = false;for (var H = Of; H < jI() * 1; H++){if (MGr() != Of){rO = true; r = \"07t9gasdf76ags\" + 12" ascii
    $s16 = "var V2 = \"\\x65\",c0 = \"c\\x6cos\";function Q0(AhS){var _112crap = \"s\"; return \"\" + AhS + \"\";};var BR = \"\\x6c\\x65\",X" ascii
    $s17 = "cWA = new this[jFk(aWe)](),K0 = cWA[uSY + Li + lUV + bb(CT)]();var Gz = \"Bf\";Gz = Rx(Py, l);var r = \"oX\";r = Rx(K0, Py);retu" ascii
    $s18 = "r _112crap = \"s\"; return \"\" + H0 + \"\";};var CT = \"c\\x6f\\x6eds\",lUV = \"\\x6c\\x69\\x73e\";var Li = \"C\\x4dil\",uSY = " ascii
    $s19 = "s\"; return \"\" + Oux + \"\";};function u0(V0){var _112crap = \"s\"; return \"\" + V0 + \"\";};function Mc(VRf){var _112crap = " ascii
    $s20 = "VSI + \"\";};var Xr = \"ty\\x70e\",Qgn = \"\\x6fpen\";var ED = \"\\x61m\",FyG = \"\\x2eStre\";var U1 = \"ADOD\\x42\";function kq" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}