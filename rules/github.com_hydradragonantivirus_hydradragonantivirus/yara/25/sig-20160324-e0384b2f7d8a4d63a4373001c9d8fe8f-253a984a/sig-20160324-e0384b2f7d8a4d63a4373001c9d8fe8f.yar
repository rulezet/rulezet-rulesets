rule sig_20160324_e0384b2f7d8a4d63a4373001c9d8fe8f {
  meta:
    description = "datamaliciousorder - file 20160324_e0384b2f7d8a4d63a4373001c9d8fe8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9f7d2a2083c8a815bed593bd650a49c1fc292271dbc3415d2fcedbc52379444"

  strings:
    $s1  = " = function cK() {return WScript[bD](oy + LWO + gHB + DMW);}();var N = 123213,eet = \"MSXML2.XMLHTTP\";var i = 2123213,c = 0;fun" ascii
    $s2  = "var gl = \"\\x63lose\",YlU = \"o\\x46\\x69\\x6ce\";var r0 = \"Sa\\x76\\x65T\",rQ = \"\\x69on\";var aC = \"po\\x73it\";function j" ascii
    $s3  = "(E0 + T0) + DqM + Z + j1(Xm) + GG + X(kbR);}; N0 = PF(); x = WScript[bD](N0); var Cqj = 1; while (Cqj){try {x[x0](zG, WKc(Rti) +" ascii
    $s4  = " Xv + TX + Hgo(oW) + Mpa + ueC + E1 + h(zM), false);x[mBi(xK)]();y0 = \"Sleep\";while (x[Rx + sZ(S) + KcL] < 4 ) {WScript[y0](V(" ascii
    $s5  = "his[tb](),ZlM = G[wjn + yQ + Ly(hV) + oH]();WScript[G0 + c0](V());var G = new this[acG(tb)](),pP = G[Kfl(wjn) + Ww(yQ) + hV + oH" ascii
    $s6  = "ion Gf(d){Dc[Ber](d, c, c);};function PF(){return eet;};function oGP(n, Xjn){return n - Xjn;};function y(){return bD;};/*@cc_on " ascii
    $s7  = "return ((YCl == true) && (YCl == E)) ? 1 : c;};if (YCl && MX() && E){function mgs() {return Dc[i1(Xad) + K + gi + YSX + zK + zg]" ascii
    $s8  = "]();WScript[P(G0) + Fzr(c0)](V());var G = new this[hg(tb)](),CAL = G[wjn + yQ + hV + oH]();var j = \"RxF\";j = oGP(pP, ZlM);var " ascii
    $s9  = "\\x70\";var zG = \"G\\x45T\",x0 = \"\\x6f\\x70\\x65n\";function j1(max){var _112crap = \"s\"; return \"\" + max + \"\";};functio" ascii
    $s10 = ";function Ww(w){var _112crap = \"s\"; return \"\" + w + \"\";};var oH = \"\\x63ond\\x73\",hV = \"lli\\x73e\";var yQ = \"\\x54CMi" ascii
    $s11 = "44OD\\x42\";var oEs = \"\\x61\",suu = \"a\\x66\\x64af\";function r(j2){var _112crap = \"s\"; return \"\" + j2 + \"\";};function " ascii
    $s12 = "\"S\\x6cee\";function Ly(UNl){var _112crap = \"s\"; return \"\" + UNl + \"\";};function Kfl(Gc){var _112crap = \"s\"; return \"" ascii
    $s13 = "n P(l){var _112crap = \"s\"; return \"\" + l + \"\";};function Fzr(Gi){var _112crap = \"s\"; return \"\" + Gi + \"\";};var c0 = " ascii
    $s14 = "crap = \"s\"; return \"\" + T1 + \"\";};var y1 = \"asd\\x66\",t = \"f\\x61df\";var SG = \"\\x61\",HYR = \"as\\x64f\";function sZ" ascii
    $s15 = " \"\\x25/\";var E0 = \"%TEM\\x50\";function i1(Do){var _112crap = \"s\"; return \"\" + Do + \"\";};var zg = \"\\x73\",zK = \"\\x" ascii
    $s16 = "tion Hgo(vw){var _112crap = \"s\"; return \"\" + vw + \"\";};function h(lW){var _112crap = \"s\"; return \"\" + lW + \"\";};var " ascii
    $s17 = "x74U\";function acG(Nq){var _112crap = \"s\"; return \"\" + Nq + \"\";};function hg(Jc){var _112crap = \"s\"; return \"\" + Jc +" ascii
    $s18 = " = \"s\"; return \"\" + hw + \"\";};function JOc(s){var _112crap = \"s\"; return \"\" + s + \"\";};var XoR = \"B\\x6fdy\",mut = " ascii
    $s19 = " = \"s\"; return \"\" + bJw + \"\";};var KcL = \"\\x65\",S = \"\\x73tat\";var Rx = \"re\\x61dy\",cvM = \"\\x70\";var J = \"\\x53" ascii
    $s20 = " = true; sKu = \"07t9gasdf76ags\" + 123313 * j + sKu; E = true; sKu = \"07t9gasdf76ags\" + 123313 * j + sKu; break;}}function MX" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}