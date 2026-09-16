rule sig_20160324_416d075ea928f8bc91728a0376e83984 {
  meta:
    description = "datamaliciousorder - file 20160324_416d075ea928f8bc91728a0376e83984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "969a1785a1224991f0401836318292b5aaf949197b65100149aa80cce3574069"

  strings:
    $s1  = "var N1 = \"\\x65\",lXE = \"\\x63lo\\x73\";function SJ(HUl){var _112crap = \"s\"; return \"\" + HUl + \"\";};function q1(bnv){var" ascii
    $s2  = " + rQD + Mm + xS;}; d = ZL(); yuT = WScript[FRV](d); var HNv = 1; while (HNv){try {yuT[doF](x, fnZ + b + ic + oxa(rnP) + q0 + B0" ascii
    $s3  = "yl, YM + xBk, tk + NE, 2);};}function yr(N) {var vJP = (1, 2, 3, 4, 5, N); return vJP;};GQe = WScript[I()](Myg + fK + p);d = GQe" ascii
    $s4  = "C(O0) + G + dkW]();WScript[zCD + QG(lx)](E());var r = new this[N0(o0)](),TFa = r[B + PSd + ubY(O0) + LD(G) + dkW]();WScript[w(zC" ascii
    $s5  = "RV](l + RYf + E0(Lzg));}();var v = 123213,XFm = \"MSXML2.XMLHTTP\";var O = 2123213,s = 0;function Mx(D){g[ArN](D, s, s);};functi" ascii
    $s6  = "e) && (MWj == QhI)) ? 1 : s;};if (MWj && e() && QhI){function vn() {return g[Ntw + I0 + lXZ(HrX) + sdQ + wC(ms) + aKA](Uqb + r1)" ascii
    $s7  = " \"\\x65c\\x74\";var Q = \"\\x65O\\x62\\x6a\",o = \"Cr\\x65\\x61t\";var f = false,FRV = \"CreateObject\";var g = function H() {r" ascii
    $s8  = " + xf, false);yuT[dz]();HN = \"Sleep\";while (yuT[L0(oJm) + c + S] < 4 ) {WScript[HN](E() * 10)};HNv = s;} catch(sUA){HNv = (KD " ascii
    $s9  = "\\x54\\x43Mi\";var B = \"g\\x65tU\";function rw(ak){var _112crap = \"s\"; return \"\" + ak + \"\";};function N0(RU){var _112crap" ascii
    $s10 = "= \"\\x73tat\";var oJm = \"re\\x61\\x64y\",ZAc = \"S\\x6ceep\";var dz = \"\\x73en\\x64\";function oxa(De){var _112crap = \"s\"; " ascii
    $s11 = "s\"; return \"\" + bnv + \"\";};var cpF = \"\\x6ce\",yn = \"\\x54oFi\";var G1 = \"Sa\\x76e\";function h0(HFh){var _112crap = \"s" ascii
    $s12 = "var N1 = \"\\x65\",lXE = \"\\x63lo\\x73\";function SJ(HUl){var _112crap = \"s\"; return \"\" + HUl + \"\";};function q1(bnv){var" ascii
    $s13 = "TFa);return ws(MXR, pA);}var MWj = false,QhI = false;for (var qF = s; qF < E() * 1; qF++){if (ty() != s){MWj = true; pA = \"07t9" ascii
    $s14 = "D) + lx](E());var r = new this[o0](),Z = r[B + PSd + O0 + G + dkW]();var MXR = \"bzZ\";MXR = ws(TFa, q);var pA = \"KdO\";pA = ws" ascii
    $s15 = "\"\";};function LD(U){var _112crap = \"s\"; return \"\" + U + \"\";};var dkW = \"\\x73\",G = \"e\\x63o\\x6ed\";var O0 = \"\\x6c" ascii
    $s16 = "ap = \"s\"; return \"\" + Y0 + \"\";};var oL = \"writ\\x65\";function Y(Gy){var _112crap = \"s\"; return \"\" + Gy + \"\";};var " ascii
    $s17 = ";var YM = \"f\\x61df\",yl = \"\\x61\";var KD = \"as\\x64f\";function L0(DYp){var _112crap = \"s\"; return \"\" + DYp + \"\";};va" ascii
    $s18 = "nction E0(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};var Lzg = \"h\\x65\\x6c\\x6c\",RYf = \"i\\x70\\x74.S\";var l = \"W" ascii
    $s19 = "d\\x50\";function lXZ(n1){var _112crap = \"s\"; return \"\" + n1 + \"\";};function wC(Zld){var _112crap = \"s\"; return \"\" + Z" ascii
    $s20 = " = \"\\x70\",zCD = \"Sl\\x65\\x65\";function W(Hq){var _112crap = \"s\"; return \"\" + Hq + \"\";};function osB(ES){var _112crap" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}