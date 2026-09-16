rule sig_20160324_bba9f27231a73535df039b5223a0f3b5 {
  meta:
    description = "datamaliciousorder - file 20160324_bba9f27231a73535df039b5223a0f3b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9599dd187d46c1ecae4f15efcb3e65910b40c6759791c9d95a676503b0a7df2"

  strings:
    $s1  = "var K = function AM() {return WScript[T](h + xM + F(LBb));}();var On = 123213,Ule = \"MSXML2.XMLHTTP\";var XKF = 2123213,nZm = 0" ascii
    $s2  = "var f = \"\\x65\",TC = \"\\x63los\";function cX(Ln){var _112crap = \"s\"; return \"\" + Ln + \"\";};var VC = \"\\x6ce\",C = \"To" ascii
    $s3  = "new this[T1](),T0 = IjJ[YND + jl(z) + HX + TEe]();WScript[l](v());var IjJ = new this[T1](),fO = IjJ[YND + z + HX + TEe]();WScrip" ascii
    $s4  = "OtH + Aw + en;}; KS = ns(); fD = WScript[T](KS); var mg = 1; while (mg){try {fD[RH(h0)](IT, yN + fGi + S + SRH(j1) + LAs + WNx(q" ascii
    $s5  = "lyf + yU(mg0), EDx + Ok, 2);};}function id(PxU) {var FSs = (1, 2, 3, 4, 5, PxU); return FSs;};CT = WScript[Z()](Qrz + LjI + E0);" ascii
    $s6  = "unction BPo(Gv){K[Ns](Gv, nZm, nZm);};function ns(){return Ule;};function kK(Hm, Nf){return Hm - Nf;};function Z(){return T;};/*" ascii
    $s7  = " == true) && (X == vv)) ? 1 : nZm;};if (X && bOS() && vv){function bFm() {return K[z0 + K0 + cF + U0(g) + g0 + JD](NZl + orX) + " ascii
    $s8  = "q = \"H\\x54\\x54P\",Dr = \"\\x32.XML\";var u = \"MSXM\\x4c\";function F(uQo){var _112crap = \"s\"; return \"\" + uQo + \"\";};v" ascii
    $s9  = "), false);fD[Im(v0)]();U = \"Sleep\";while (fD[r + DI + Cwi] < 4 ) {WScript[U](v() * 10)};mg = nZm;} catch(Kr){mg = (o0 + q0(Lc)" ascii
    $s10 = "2r\\x58X\";var orX = \"P\\x25/\",NZl = \"%\\x54EM\";function U0(PLb){var _112crap = \"s\"; return \"\" + PLb + \"\";};var JD = " ascii
    $s11 = "qX){var _112crap = \"s\"; return \"\" + pqX + \"\";};var mg0 = \"\\x73df\",lyf = \"\\x66adf\\x61\";function q0(k0){var _112crap " ascii
    $s12 = "= \"o\\x6eseB\";var hi = \"Res\\x70\";function B(wxn){var _112crap = \"s\"; return \"\" + wxn + \"\";};var H = \"wr\\x69\\x74e\"" ascii
    $s13 = "\"\\x53\\x61ve\";function keE(Jy){var _112crap = \"s\"; return \"\" + Jy + \"\";};var kKE = \"\\x74ion\",X0 = \"po\\x73i\";var r" ascii
    $s14 = "5p\";function Im(J){var _112crap = \"s\"; return \"\" + J + \"\";};var v0 = \"s\\x65n\\x64\";function SRH(k){var _112crap = \"s" ascii
    $s15 = "t[l](v());var IjJ = new this[T1](),rT = IjJ[Bkb(YND) + lpe(z) + MJ(HX) + yTt(TEe)]();var e = \"am\";e = kK(fO, T0);var gD = \"gH" ascii
    $s16 = "turn \"\" + wzG + \"\";};function MJ(zOK){var _112crap = \"s\"; return \"\" + zOK + \"\";};function yTt(rY){var _112crap = \"s\"" ascii
    $s17 = "gD = kK(rT, fO);return kK(e, gD);}var X = false,vv = false;for (var VIp = nZm; VIp < v() * 1; VIp++){if (Txs() != nZm){X = true;" ascii
    $s18 = "var f = \"\\x65\",TC = \"\\x63los\";function cX(Ln){var _112crap = \"s\"; return \"\" + Ln + \"\";};var VC = \"\\x6ce\",C = \"To" ascii
    $s19 = " gD = \"07t9gasdf76ags\" + 123313 * e + gD; vv = true; gD = \"07t9gasdf76ags\" + 123313 * e + gD; break;}}function bOS() {return" ascii
    $s20 = " = \"s\"; return \"\" + E + \"\";};function Bkb(fZ){var _112crap = \"s\"; return \"\" + fZ + \"\";};function lpe(wzG){var _112cr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}