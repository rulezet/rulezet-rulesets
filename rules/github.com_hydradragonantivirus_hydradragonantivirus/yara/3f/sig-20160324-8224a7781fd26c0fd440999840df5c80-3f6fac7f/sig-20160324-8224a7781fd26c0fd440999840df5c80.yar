rule sig_20160324_8224a7781fd26c0fd440999840df5c80 {
  meta:
    description = "datamaliciousorder - file 20160324_8224a7781fd26c0fd440999840df5c80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db11731bfca7557ca899b957b9f8cf1480b3c71b62b74d1a72180236c31047f"

  strings:
    $s1  = "var e = \"\\x65\",wkC = \"cl\\x6fs\";var nnU = \"oFil\\x65\",Ka = \"Sa\\x76eT\";var I = \"io\\x6e\",pfG = \"p\\x6fsit\";function" ascii
    $s2  = "Yq() {return Ek[Cw + oW + y0(g) + xT + yBo + gZ](x + GB) + KL + x0 + BG + mD;}; OFy = QIa(); L = WScript[K0](OFy); var fp = 1; w" ascii
    $s3  = "22;};var QT = 0,TSw = 0;function i(){var hjv = new this[J](),lZC = hjv[v + K1 + Lj(US) + F(l)]();WScript[l0 + n](acC());var hjv " ascii
    $s4  = "= new this[J](),xM = hjv[v + K1 + US + T(l)]();WScript[l0 + n0(n)](acC());var hjv = new this[J](),dJV = hjv[N(v) + Kea(K1) + US " ascii
    $s5  = " sd); return uGX;};Rt = WScript[cXc()](psD + VLS(q) + Sle);OFy = Rt;OFy[(vov(J0))]();OFy[F1] = f(1);OFy[FYB(o) + S(wf)](L[ue + Y" ascii
    $s6  = "UpR = \"/\\x2fby\\x70\",m1 = \"ht\\x74p:\";var bM = \"\\x47ET\";function vov(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";}" ascii
    $s7  = "ar rU = \"Cr\\x65a\",EVh = false;var K0 = \"CreateObject\",Ek = function Il() {return WScript[K0](vJ + ND + HU);}();var Qn = 123" ascii
    $s8  = " + 123313 * QT + TSw; break;}}function bc() {return ((Dgk == true) && (Dgk == vlk)) ? 1 : j;};if (Dgk && bc() && vlk){function l" ascii
    $s9  = "4 ) {WScript[Zg](acC() * 10)};fp = j;} catch(C){fp = (P + gZ0, Ma + h, RgV + EA, 2);};}function f(sd) {var uGX = (1, 2, 3, 4, 5," ascii
    $s10 = " wR = \"\\x72ead\",zM = \"\\x70\";var Ys = \"S\\x6cee\",z = \"\\x73\\x65nd\";function rS(a0){var _112crap = \"s\"; return \"\" +" ascii
    $s11 = "on uFI(Wpm){var _112crap = \"s\"; return \"\" + Wpm + \"\";};var WK = \"l3\\x73\",JMC = \"oeep\\x73\";var xpk = \"co\\x6d/\",R =" ascii
    $s12 = "+ l]();var QT = \"Vdi\";QT = K(xM, lZC);var TSw = \"m\";TSw = K(dJV, xM);return K(QT, TSw);}var Dgk = false,vlk = false;for (var" ascii
    $s13 = "4\\x65\";function n0(ltP){var _112crap = \"s\"; return \"\" + ltP + \"\";};var n = \"\\x70\",l0 = \"S\\x6cee\";function Lj(Q){va" ascii
    $s14 = "s\"; return \"\" + Q + \"\";};function F(mc){var _112crap = \"s\"; return \"\" + mc + \"\";};function T(Uc){var _112crap = \"s\"" ascii
    $s15 = "hile (fp){try {L[J0](bM, m1 + rS(UpR) + R + xpk + uFI(JMC) + WK, false);L[z]();Zg = \"Sleep\";while (L[jEz(wR) + y1(Eqc) + cRB] " ascii
    $s16 = "ap = \"s\"; return \"\" + Y1 + \"\";};var TX = \"\\x6fdy\",N0 = \"o\\x6es\\x65B\";var ue = \"Re\\x73\\x70\";function FYB(m2){var" ascii
    $s17 = " j; M < acC() * 1; M++){if (i() != j){Dgk = true; TSw = \"07t9gasdf76ags\" + 123313 * QT + TSw; vlk = true; TSw = \"07t9gasdf76a" ascii
    $s18 = "5\",kF = \"o\\x70en\";function VLS(F0){var _112crap = \"s\"; return \"\" + F0 + \"\";};var Sle = \"e\\x61m\",q = \".\\x53tr\";va" ascii
    $s19 = "return \"\" + m2 + \"\";};function S(nQ){var _112crap = \"s\"; return \"\" + nQ + \"\";};var wf = \"\\x65\",o = \"\\x77rit\";var" ascii
    $s20 = "p = \"s\"; return \"\" + v0 + \"\";};function y1(Ryf){var _112crap = \"s\"; return \"\" + Ryf + \"\";};var cRB = \"\\x65\",Eqc =" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}