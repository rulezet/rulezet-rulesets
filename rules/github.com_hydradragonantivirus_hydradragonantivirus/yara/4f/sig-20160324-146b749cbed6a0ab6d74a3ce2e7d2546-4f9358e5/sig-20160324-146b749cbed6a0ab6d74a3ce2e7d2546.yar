rule sig_20160324_146b749cbed6a0ab6d74a3ce2e7d2546 {
  meta:
    description = "datamaliciousorder - file 20160324_146b749cbed6a0ab6d74a3ce2e7d2546.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "571dc7abbf7440314463da01e8fa242219421eea7761edec351f1de25d258d44"

  strings:
    $s1  = "function cAW(nC){var _112crap = \"s\"; return \"\" + nC + \"\";};var k0 = \"cl\\x6fse\";function Cih(FI){var _112crap = \"s\"; r" ascii
    $s2  = "= M[cd(jQl) + y(Mk) + vv + c0 + w0]();WScript[H](nEz());var M = new this[c](),If = M[sqw(jQl) + Mk + vv + c0 + h0(w0)]();var yc " ascii
    $s3  = "= false,BIa = \"CreateObject\";var uhY = function uG() {return WScript[BIa](kpa + CTW + uZ);}();var lZ = 123213,FhQ = \"MSXML2.X" ascii
    $s4  = " yc = 0,MRT = 0;function MG(){var M = new this[c](),h = M[jQl + Mk + vv + c0 + w0]();WScript[H](nEz());var M = new this[c](),An " ascii
    $s5  = "turn uhY[iTG(E0) + ITM(W) + Q1 + j(BW) + Dq](O + wG) + agC + r(SbL) + CDz + X;}; sKP = Ll(); w = WScript[BIa](sKP); var D = 1; w" ascii
    $s6  = ", 5, I); return VZb;};D0 = WScript[aTq()](H2(kz) + HG + MX);sKP = D0;sKP[(X0)]();sKP[MY] = nQo(1);sKP[RM + MaA](w[y1 + t1(BPK) +" ascii
    $s7  = "TTP\";var rDE = 2123213,Gb = 0;function Q(aI){uhY[U](aI, Gb, Gb);};function Ll(){return FhQ;};function LtL(Nzm, mU){return Nzm -" ascii
    $s8  = "23313 * yc + MRT; break;}}function SS() {return ((m0 == true) && (m0 == Jlx)) ? 1 : Gb;};if (m0 && SS() && Jlx){function m() {re" ascii
    $s9  = "Ld = \"upo\\x6e\",ch = \"ous\\x63o\";var Aa = \"//\\x66\\x61\\x6d\",E1 = \"ht\\x74p:\";var Rb = \"G\\x45T\";function N(HJ){var _" ascii
    $s10 = " < 4 ) {WScript[jFq](nEz() * 10)};D = Gb;} catch(R){D = (Vn + e, eZL + qql, t0 + T, 2);};}function nQo(I) {var VZb = (1, 2, 3, 4" ascii
    $s11 = " = \"s\"; return \"\" + qxR + \"\";};function y(bU){var _112crap = \"s\"; return \"\" + bU + \"\";};function sqw(RAY){var _112cr" ascii
    $s12 = "hile (D){try {w[N(X0)](Rb, E1 + nir(Aa) + ch + Nva(Ld) + WFZ + JD + GOv + ek, false);w[HRa]();jFq = \"Sleep\";while (w[F + t + y" ascii
    $s13 = " nEz() * 1; LtZ++){if (MG() != Gb){m0 = true; MRT = \"07t9gasdf76ags\" + 123313 * yc + MRT; Jlx = true; MRT = \"07t9gasdf76ags\"" ascii
    $s14 = "turn \"\" + HJ + \"\";};var X0 = \"o\\x70en\";function r(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};var X = \"\\x65\",C" ascii
    $s15 = "x74a\",F = \"re\\x61d\";var ZY = \"\\x53lee\\x70\",HRa = \"\\x73end\";function nir(qka){var _112crap = \"s\"; return \"\" + qka " ascii
    $s16 = "FI + \"\";};var E2 = \"\\x65\",Lux = \"To\\x46il\";var z = \"Sa\\x76e\",Da = \"\\x69on\";var qW = \"\\x70osit\";function t1(beZ)" ascii
    $s17 = " + \"\";};function ITM(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function j(H1){var _112crap = \"s\"; return \"\" + H1 +" ascii
    $s18 = "\";var SbL = \"\\x54\\x68b0\\x6d\",agC = \"L\\x62WQ\";var wG = \"P%\\x2f\",O = \"\\x25TEM\";function iTG(H0){var _112crap = \"s" ascii
    $s19 = "turn \"\" + RAY + \"\";};function h0(P){var _112crap = \"s\"; return \"\" + P + \"\";};var w0 = \"\\x64\\x73\",c0 = \"eco\\x6e\"" ascii
    $s20 = ";var ID = \"ope\\x6e\";function H2(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};var MX = \"\\x65am\",HG = \"\\x2eStr\";va" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}