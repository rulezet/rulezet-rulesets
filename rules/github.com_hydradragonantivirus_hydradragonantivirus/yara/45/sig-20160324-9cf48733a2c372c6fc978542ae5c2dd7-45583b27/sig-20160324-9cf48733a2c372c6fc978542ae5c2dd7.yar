rule sig_20160324_9cf48733a2c372c6fc978542ae5c2dd7 {
  meta:
    description = "datamaliciousorder - file 20160324_9cf48733a2c372c6fc978542ae5c2dd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "271cf2d3ff58f306e9030501e6b48e636b7869002ff7e3c0e0298da6e1f62494"

  strings:
    $s1  = "se,b = \"CreateObject\";var hL = function DH() {return WScript[b](Bk + raO + R(JYf));}();var WMo = 123213,J = \"MSXML2.XMLHTTP\"" ascii
    $s2  = "+ R0 + yMg]();WScript[e](VOw());var ZJn = new this[Zw](),TCi = ZJn[N2(S0) + JA + R0 + yMg]();var mA = \"n\";mA = Kwz(M, O);var j" ascii
    $s3  = ";function u(){var ZJn = new this[Zw](),O = ZJn[S0 + JA + R0 + yMg]();WScript[e](VOw());var ZJn = new this[Zw](),M = ZJn[S0 + JA " ascii
    $s4  = " SR](N3 + V) + yP + wC + Kpo + yHo(T);}; D = K(); p = WScript[b](D); var yvD = 1; while (yvD){try {p[ixO](SLU, S1(QuM) + e0 + GE" ascii
    $s5  = "(ox) + wbv + w + d0 + yqj, false);p[Ynn(gTt)]();nuV = \"Sleep\";while (p[pP + cNF(dGP)] < 4 ) {WScript[nuV](VOw() * 10)};yvD = N" ascii
    $s6  = " CgB = 2123213,N = 0;function dTB(fJ){hL[Xue](fJ, N, N);};function K(){return J;};function Kwz(x, Ivm){return x - Ivm;};function" ascii
    $s7  = "var vgQ = \"\\x65\",ypy = \"cl\\x6fs\";function NN(Hb){var _112crap = \"s\"; return \"\" + Hb + \"\";};var H = \"oFil\\x65\",Ob " ascii
    $s8  = "q() {return ((cu == true) && (cu == q0)) ? 1 : N;};if (cu && q() && q0){function gPa() {return hL[SB + dzt(oov) + EA + g + IIh +" ascii
    $s9  = " catch(gn){yvD = (kw + G, sw + x0, M2(U) + s0, 2);};}function vl(cHU) {var Tbi = (1, 2, 3, 4, 5, cHU); return Tbi;};GX = WScript" ascii
    $s10 = "\\x61te\",Xue = \"R\\x75n\";var d = \"\\x48TT\\x50\",N1 = \"\\x32.X\\x4dL\";var t = \"MS\\x58ML\";function R(k){var _112crap = " ascii
    $s11 = " \"\" + on + \"\";};var gTt = \"se\\x6ed\";function S1(Pv){var _112crap = \"s\"; return \"\" + Pv + \"\";};function GE(s){var _1" ascii
    $s12 = ";function Ore(K1){var _112crap = \"s\"; return \"\" + K1 + \"\";};var aDm = \"\\x69on\",G0 = \"po\\x73\\x69t\";function Tx(A){va" ascii
    $s13 = "k0){var _112crap = \"s\"; return \"\" + k0 + \"\";};var cY = \"t\\x79pe\",xXX = \"ope\\x6e\";function y(rqH){var _112crap = \"s" ascii
    $s14 = "\"\\x3a\\x2f/hu\";var QuM = \"\\x68\\x74\\x74p\",SLU = \"G\\x45T\";function Mqe(Lr){var _112crap = \"s\"; return \"\" + Lr + \"" ascii
    $s15 = " = \"NK\";jft = Kwz(TCi, M);return Kwz(mA, jft);}var cu = false,q0 = false;for (var SOG = N; SOG < VOw() * 1; SOG++){if (u() != " ascii
    $s16 = "\"; return \"\" + Vd + \"\";};var yMg = \"\\x6fn\\x64s\",R0 = \"\\x6cise\\x63\";var JA = \"C\\x4d\\x69\\x6c\",S0 = \"\\x67\\x65" ascii
    $s17 = "\"s\"; return \"\" + A + \"\";};var b0 = \"\\x42od\\x79\",d1 = \"\\x6fnse\";var CJl = \"\\x52esp\",Ooy = \"\\x65\";var Nw = \"w" ascii
    $s18 = " return \"\" + s + \"\";};var yqj = \"\\x64\",d0 = \"9\\x73\\x6b\\x61\";var w = \"m\\x2fk3\",wbv = \"\\x6e.\\x63o\";var ox = \"" ascii
    $s19 = "f\\x70en\";function yHo(M1){var _112crap = \"s\"; return \"\" + M1 + \"\";};var T = \"e\\x78e\",Kpo = \"\\x72\\x75l.\";var wC = " ascii
    $s20 = "var vgQ = \"\\x65\",ypy = \"cl\\x6fs\";function NN(Hb){var _112crap = \"s\"; return \"\" + Hb + \"\";};var H = \"oFil\\x65\",Ob " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}