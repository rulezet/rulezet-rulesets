rule sig_20160324_36493f6d4aba8dc436e877ec56f507c8 {
  meta:
    description = "datamaliciousorder - file 20160324_36493f6d4aba8dc436e877ec56f507c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c8cd9566f9f9af17971cc53c329a218a252cd89c87da4cc99f5962f0c26eb0e"

  strings:
    $s1  = "ect\";var M = function v() {return WScript[kq](Yc + vtI(cS) + Hki);}();var s = 123213,Osj = \"MSXML2.XMLHTTP\";var lzE = 2123213" ascii
    $s2  = "function AE(TD){var _112crap = \"s\"; return \"\" + TD + \"\";};var Rz = \"\\x65\",v2 = \"\\x63los\";function gd(bg){var _112cra" ascii
    $s3  = "D + p + N(KOs) + E]();WScript[EJ](frQ());var ocl = new this[k](),Tv = ocl[VD + p + KOs + E]();var sU = \"fWM\";sU = YE(pR, gGX);" ascii
    $s4  = "NU + Da + cJU(b) + c + r + RKw + c0(q), false);RxF[N0(ce)]();aTa = \"Sleep\";while (RxF[Brs + tE + vA] < 4 ) {WScript[aTa](frQ()" ascii
    $s5  = " S(ee)](NA + DCw) + HL + EL + Rgc + vv + WA;}; P = rg(); RxF = WScript[kq](P); var wRt = 1; while (wRt){try {RxF[qa](lut, Tz + N" ascii
    $s6  = "F(){var ocl = new this[GMN(k)](),gGX = ocl[VD + RYm(p) + KOs + E]();WScript[wH(EJ)](frQ());var ocl = new this[A(k)](),pR = ocl[V" ascii
    $s7  = "w = 0;function IN(hZe){M[nlZ](hZe, UIw, UIw);};function rg(){return Osj;};function YE(Gj, GTD){return Gj - GTD;};function x(){re" ascii
    $s8  = "on bRd() {return ((gL == true) && (gL == tS)) ? 1 : UIw;};if (gL && bRd() && tS){function aJ() {return M[Fq + oq + fL + Pp + T +" ascii
    $s9  = " wVs = \"H\\x54TP\",i = \"\\x32.XML\";var B0 = \"\\x4dSX\\x4d\\x4c\";function vtI(qNS){var _112crap = \"s\"; return \"\" + qNS +" ascii
    $s10 = " return \"\" + hy + \"\";};var EJ = \"Sle\\x65p\";function RYm(zpj){var _112crap = \"s\"; return \"\" + zpj + \"\";};function N(" ascii
    $s11 = "function AE(TD){var _112crap = \"s\"; return \"\" + TD + \"\";};var Rz = \"\\x65\",v2 = \"\\x63los\";function gd(bg){var _112cra" ascii
    $s12 = " \"\\x70\",Y0 = \"Sl\\x65e\";function N0(RLL){var _112crap = \"s\"; return \"\" + RLL + \"\";};var ce = \"s\\x65nd\";function cJ" ascii
    $s13 = "0(Uei){var _112crap = \"s\"; return \"\" + Uei + \"\";};var Jih = \"\\x61\",w0 = \"af\\x64af\";function p0(IW){var _112crap = \"" ascii
    $s14 = "2crap = \"s\"; return \"\" + T0 + \"\";};var EjP = \"od\\x79\",A0 = \"o\\x6eseB\";var v0 = \"\\x52esp\";function sbZ(Wk){var _11" ascii
    $s15 = "ap = \"s\"; return \"\" + a + \"\";};function c0(nIy){var _112crap = \"s\"; return \"\" + nIy + \"\";};var q = \"3o\\x61s\",RKw " ascii
    $s16 = "x25/\";var NA = \"\\x25TE\\x4dP\";function S(Et){var _112crap = \"s\"; return \"\" + Et + \"\";};var ee = \"\\x73\",T = \"\\x72i" ascii
    $s17 = "\";};function n(P0){var _112crap = \"s\"; return \"\" + P0 + \"\";};var cN = \"ea\\x6d\",Zy = \"B.S\\x74r\";var wke = \"\\x41DO" ascii
    $s18 = "rap = \"s\"; return \"\" + GB + \"\";};var E = \"\\x63on\\x64s\",KOs = \"li\\x73e\";var p = \"C\\x4d\\x69l\",VD = \"ge\\x74UT\";" ascii
    $s19 = "_112crap = \"s\"; return \"\" + R + \"\";};function A(w){var _112crap = \"s\"; return \"\" + w + \"\";};var k = \"\\x44ate\",nlZ" ascii
    $s20 = "r GAk = \"Y\";GAk = YE(Tv, pR);return YE(sU, GAk);}var gL = false,tS = false;for (var OE = UIw; OE < frQ() * 1; OE++){if (F() !=" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}