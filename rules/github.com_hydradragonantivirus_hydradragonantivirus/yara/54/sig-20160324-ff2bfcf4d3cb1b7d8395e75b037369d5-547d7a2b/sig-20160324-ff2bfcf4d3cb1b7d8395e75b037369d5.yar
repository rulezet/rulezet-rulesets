rule sig_20160324_ff2bfcf4d3cb1b7d8395e75b037369d5 {
  meta:
    description = "datamaliciousorder - file 20160324_ff2bfcf4d3cb1b7d8395e75b037369d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6c6799bb2071c5fda663c671177b5f0ba0da36dbb2d5502ea3db071fbc9945f"

  strings:
    $s1  = "function Bdu(OI){var _112crap = \"s\"; return \"\" + OI + \"\";};var k = \"\\x65\",YM = \"cl\\x6fs\";var P1 = \"o\\x46ile\",jj =" ascii
    $s2  = " + LDF]();WScript[nMD(HwW) + zru](v());var FQY = new this[PU](),miw = FQY[R(Rvh) + c(nvu) + Z1(Bw) + LDF]();WScript[eS(HwW) + zr" ascii
    $s3  = "SF;}; b0 = x(); SE = WScript[Zp](b0); var EBd = 1; while (EBd){try {SE[Ta](VP(OF), BBa + Tw + teg(A0) + P + nQa + ALY + V, false" ascii
    $s4  = "g = \"jec\\x74\",Y = \"te\\x4fb\";var zi = \"Cre\\x61\",cB = false;var Zp = \"CreateObject\",xPa = function sKf() {return WScrip" ascii
    $s5  = " g1 + X0, 2);};}function OO(aNt) {var UUf = (1, 2, 3, 4, 5, aNt); return UUf;};KBx = WScript[h()](KZD + q1 + uP);b0 = KBx;b0[(Ta" ascii
    $s6  = "z + Y0 + oju(Aa));}();var r = 123213,e = \"MSXML2.XMLHTTP\";var vtz = 2123213,KlN = 0;function Z0(EXh){xPa[v0](EXh, KlN, KlN);};" ascii
    $s7  = "s\" + 123313 * HSr + O; ez = true; O = \"07t9gasdf76ags\" + 123313 * HSr + O; break;}}function PNu() {return ((IZz == true) && (" ascii
    $s8  = " == ez)) ? 1 : KlN;};if (IZz && PNu() && ez){function Z() {return xPa[NY + q + qC + Ihb + Tfz + H](U(r0) + krp) + sT + rE(h0) + " ascii
    $s9  = "2er\",Tw = \"\\x2f\\x2fti\";var BBa = \"http\\x3a\";function VP(uJ){var _112crap = \"s\"; return \"\" + uJ + \"\";};var OF = \"" ascii
    $s10 = ");SE[Q0]();YcI = \"Sleep\";while (SE[CC + B0 + i0] < 4 ) {WScript[YcI](v() * 10)};EBd = KlN;} catch(b){EBd = (ai + UZ, I0 + q0(y" ascii
    $s11 = "\\x6cise\";var qsr = \"T\\x43\\x4dil\",pW = \"\\x67et\\x55\";var Bs = \"Da\\x74\\x65\";function nMD(L){var _112crap = \"s\"; ret" ascii
    $s12 = "rue;  @end@*/if (cB){function v(){return 22;};var HSr = 0,O = 0;function f(){var FQY = new this[PU](),A = FQY[Rvh + nvu + f0(Bw)" ascii
    $s13 = "tion U(x1){var _112crap = \"s\"; return \"\" + x1 + \"\";};var krp = \"%\\x2f\",r0 = \"\\x25T\\x45MP\";var H = \"\\x73\",Tfz = " ascii
    $s14 = "12crap = \"s\"; return \"\" + Q + \"\";};var V = \"k3i\\x73a\",ALY = \"co\\x6d\\x2f\";var nQa = \"ar\\x61.\",P = \"s\\x61u\\x64" ascii
    $s15 = "};function eS(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};var zru = \"\\x70\",HwW = \"Sl\\x65\\x65\";function f0(Rj){var" ascii
    $s16 = "function Bdu(OI){var _112crap = \"s\"; return \"\" + OI + \"\";};var k = \"\\x65\",YM = \"cl\\x6fs\";var P1 = \"o\\x46ile\",jj =" ascii
    $s17 = "urn x0(HSr, O);}var IZz = false,ez = false;for (var wO = KlN; wO < v() * 1; wO++){if (f() != KlN){IZz = true; O = \"07t9gasdf76a" ascii
    $s18 = "ction oeF(ZYe){var _112crap = \"s\"; return \"\" + ZYe + \"\";};function Ove(Nw){var _112crap = \"s\"; return \"\" + Nw + \"\";}" ascii
    $s19 = "ion oju(rc){var _112crap = \"s\"; return \"\" + rc + \"\";};var Aa = \"\\x6c\",Y0 = \"Sh\\x65l\";var z = \"i\\x70\\x74.\",KE = " ascii
    $s20 = "s\"; return \"\" + Rj + \"\";};function R(dtJ){var _112crap = \"s\"; return \"\" + dtJ + \"\";};function c(FaF){var _112crap = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}