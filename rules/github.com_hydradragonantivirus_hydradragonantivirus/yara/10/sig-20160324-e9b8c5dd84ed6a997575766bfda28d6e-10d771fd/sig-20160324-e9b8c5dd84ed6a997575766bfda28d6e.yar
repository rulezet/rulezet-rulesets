rule sig_20160324_e9b8c5dd84ed6a997575766bfda28d6e {
  meta:
    description = "datamaliciousorder - file 20160324_e9b8c5dd84ed6a997575766bfda28d6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "786d00701a9d855ea318fded229cbaf4a55bb9aa5c07d494ab13a4e79725c7be"

  strings:
    $s1  = "var YSo = \"clos\\x65\",B = \"\\x6ce\";var ly = \"ToF\\x69\",cU = \"S\\x61ve\";var ZY = \"\\x74\\x69on\",l0 = \"pos\\x69\";var p" ascii
    $s2  = "se,v = \"CreateObject\";var bM = function O() {return WScript[v](x + K0 + OG(kUJ));}();var w = 123213,K = \"MSXML2.XMLHTTP\";var" ascii
    $s3  = "fL + bx(TG) + Y0 + BN + bWS + Up + hd(J), false);Mm[VrP]();CM = \"Sleep\";while (Mm[EdC + BD] < 4 ) {WScript[CM](Try() * 10)};cy" ascii
    $s4  = "function LD(){var GLk = new this[kXV](),d = GLk[nX + lV + R + sZ + Y]();WScript[jx(weD)](Try());var GLk = new this[kXV](),rh = G" ascii
    $s5  = "Od + g1(g0) + HuA + N](n + W) + cST + G0 + FRG;}; KND = Zr(); Mm = WScript[v](KND); var cyi = 1; while (cyi){try {Mm[cL](eJ(z), " ascii
    $s6  = "Lk[nX + lV + NAn(R) + sZ + Y]();WScript[weD](Try());var GLk = new this[kXV](),Ah = GLk[Of(nX) + fN(lV) + R + sZ + Y]();var Uc = " ascii
    $s7  = "= 2123213,PE = 0;function uEB(AKa){bM[p0](AKa, PE, PE);};function Zr(){return K;};function Zfl(fef, ZLZ){return fef - ZLZ;};func" ascii
    $s8  = "; break;}}function s() {return ((C == true) && (C == mEh)) ? 1 : PE;};if (C && s() && mEh){function vA() {return bM[nzq + Dto + " ascii
    $s9  = "= PE;} catch(G){cyi = (qdy, vK + r, Et + hX, 2);};}function vfh(b) {var H = (1, 2, 3, 4, 5, b); return H;};p = WScript[l()](sMB " ascii
    $s10 = "p0 = \"Ru\\x6e\",xg = \"\\x4c\\x48TT\\x50\";var tjo = \"\\x32.X\\x4d\",MiS = \"\\x4dSXML\";function OG(SOp){var _112crap = \"s\"" ascii
    $s11 = "; Cg++){if (LD() != PE){C = true; oh = \"07t9gasdf76ags\" + 123313 * Uc + oh; mEh = true; oh = \"07t9gasdf76ags\" + 123313 * Uc " ascii
    $s12 = "on g1(no){var _112crap = \"s\"; return \"\" + no + \"\";};var N = \"\\x6egs\",HuA = \"Str\\x69\";var g0 = \"\\x6dent\",Od = \"ir" ascii
    $s13 = "ap = \"s\"; return \"\" + D + \"\";};function Of(i){var _112crap = \"s\"; return \"\" + i + \"\";};function fN(fnB){var _112crap" ascii
    $s14 = "1\\x74h\\x6fn\";var Y0 = \"llr\\x75n\",TG = \":/\\x2ffa\";var fL = \"\\x68ttp\";function eJ(O0){var _112crap = \"s\"; return \"" ascii
    $s15 = "\"L\";Uc = Zfl(rh, d);var oh = \"y\";oh = Zfl(Ah, rh);return Zfl(Uc, oh);}var C = false,mEh = false;for (var Cg = PE; Cg < Try()" ascii
    $s16 = "ate\",EdC = \"r\\x65ady\";var G1 = \"\\x70\",MPa = \"S\\x6cee\";var VrP = \"sen\\x64\";function bx(wmM){var _112crap = \"s\"; re" ascii
    $s17 = " \"\";};function hd(Kr){var _112crap = \"s\"; return \"\" + Kr + \"\";};var J = \"\\x6fa\",Up = \"p\\x779e\";var bWS = \".\\x63" ascii
    $s18 = "etU\\x54\",F = \"Da\\x74e\";function jx(it){var _112crap = \"s\"; return \"\" + it + \"\";};var weD = \"S\\x6ceep\";function NAn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}