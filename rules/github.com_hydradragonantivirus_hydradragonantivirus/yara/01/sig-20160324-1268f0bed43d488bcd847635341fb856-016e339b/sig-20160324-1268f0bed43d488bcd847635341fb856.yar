rule sig_20160324_1268f0bed43d488bcd847635341fb856 {
  meta:
    description = "datamaliciousorder - file 20160324_1268f0bed43d488bcd847635341fb856.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1a85cefa3d7def61dea62e58d0bac556eac788cd4b2fb80f5dc72577dcc11aa"

  strings:
    $s1  = "function A0(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};var PMG = \"c\\x6cos\\x65\";function Jw(uFB){var _112crap = \"s" ascii
    $s2  = "& Ras){function hkY() {return La[WK + RNu + eLH + jR + v0](Bo + DR(bw)) + mJK + PY + Yj + XpA;}; c = ah(); z = WScript[wEg](c); " ascii
    $s3  = " = (1, 2, 3, 4, 5, N); return y;};ZT = WScript[EY()](JZ + eO + cGF);c = ZT;c[(SzK)]();c[cO(h2)] = v(1);c[jJ + aN(J0)](z[sBM + N1" ascii
    $s4  = "JW + yz]();WScript[wC(TX)](WP());var a = new this[oS(N0)](),Z = a[ZgG + xj(Y) + xJW + iEW(yz)]();WScript[TX](WP());var a = new t" ascii
    $s5  = ";function ah(){return A;};function Sd(wN, FGi){return wN - FGi;};function EY(){return wEg;};/*@cc_on  @if (@_win32 || @_win64)  " ascii
    $s6  = "e; F = \"07t9gasdf76ags\" + 123313 * Zg + F; break;}}function vL() {return ((d == true) && (d == Ras)) ? 1 : bPP;};if (d && vL()" ascii
    $s7  = "ipt[wEg](jn + iBP + R);}();var na = 123213,A = \"MSXML2.XMLHTTP\";var uP = 2123213,bPP = 0;function h(cOe){La[mE](cOe, bPP, bPP)" ascii
    $s8  = "HK + ZXU + oO] < 4 ) {WScript[nMs](WP() * 10)};re = bPP;} catch(VoB){re = (sR, z0 + AS, uu(kt) + DsA, 2);};}function v(N) {var y" ascii
    $s9  = "r Y = \"C\\x4d\\x69\\x6c\",ZgG = \"\\x67et\\x55T\";function oS(mU){var _112crap = \"s\"; return \"\" + mU + \"\";};var N0 = \"Da" ascii
    $s10 = " = \"ons\\x65\",sBM = \"\\x52\\x65sp\";function aN(VW){var _112crap = \"s\"; return \"\" + VW + \"\";};var J0 = \"\\x65\",jJ = " ascii
    $s11 = "tion cO(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";};var h2 = \"\\x74y\\x70e\",Vsu = \"\\x6fpen\";var cGF = \"ea\\x6d\",e" ascii
    $s12 = "5tU\",I = \"D\\x61te\";function wC(Hh){var _112crap = \"s\"; return \"\" + Hh + \"\";};var TX = \"Sl\\x65\\x65p\";function xj(E)" ascii
    $s13 = "  O0 = true;  @end@*/if (O0){function WP(){return 22;};var Zg = 0,F = 0;function VPC(){var a = new this[N0](),h0 = a[ZgG + Y + x" ascii
    $s14 = "var re = 1; while (re){try {z[SzK](ULD, m0 + Lc + XWn + eyo(VM) + ZP + E1(LHw) + h1(ll), false);z[XH]();nMs = \"Sleep\";while (z" ascii
    $s15 = "var XH = \"\\x73\\x65\\x6ed\";function eyo(aMz){var _112crap = \"s\"; return \"\" + aMz + \"\";};function E1(Bl0){var _112crap =" ascii
    $s16 = "function A0(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};var PMG = \"c\\x6cos\\x65\";function Jw(uFB){var _112crap = \"s" ascii
    $s17 = "his[N0](),O = a[ZgG + Y + xJW + yz]();var Zg = \"D\";Zg = Sd(Z, h0);var F = \"kY\";F = Sd(O, Z);return Sd(Zg, F);}var d = false," ascii
    $s18 = "= \"s\"; return \"\" + E + \"\";};function iEW(Ip){var _112crap = \"s\"; return \"\" + Ip + \"\";};var yz = \"c\\x6fn\\x64s\",xJ" ascii
    $s19 = "ar JZ = \"ADO\\x44\";function uu(he){var _112crap = \"s\"; return \"\" + he + \"\";};var DsA = \"f\\x61\",kt = \"a\\x66da\";var " ascii
    $s20 = "n \"\" + Bl0 + \"\";};function h1(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};var ll = \"k3i\\x73a\",LHw = \"\\x2e\\x63" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}