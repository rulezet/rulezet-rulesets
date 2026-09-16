rule sig_20160324_0b2fa53969582b5fa082e9785a24a755 {
  meta:
    description = "datamaliciousorder - file 20160324_0b2fa53969582b5fa082e9785a24a755.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c46ed602b8a4674f4ff70ba7d5d64de7a695da3f38505c1663429edf507061ba"

  strings:
    $s1  = "var N = \"clos\\x65\";function xdX(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};var YW = \"\\x65\",Ig = \"T\\x6fF\\x69\\x" ascii
    $s2  = "a\";var Y0 = \"//e\\x6dp\",QcQ = \"\\x68ttp:\";var IJ = \"GE\\x54\";function V0(VDj){var _112crap = \"s\"; return \"\" + VDj + " ascii
    $s3  = "A(u)](),s0 = emb[Npk(A) + aQG(bo) + yPz(Lni) + r(o)]();WScript[L0 + rIM](qoh());var emb = new this[qsQ(u)](),B0 = emb[A + bo + L" ascii
    $s4  = " H0 + WcO(yyn) + pKH(i1) + Gl(a0) + hvA](puM(UN) + XNj) + sv + q0 + jI + tsn;}; C = H(); J = WScript[YDJ](C); var B = 1; while (" ascii
    $s5  = ",JG = 0;function s(){var emb = new this[u](),ljs = emb[A + Y(bo) + Lni + o]();WScript[L0 + eTn(rIM)](qoh());var emb = new this[P" ascii
    $s6  = " false,YDJ = \"CreateObject\";var P0 = function Z() {return WScript[YDJ](b(hGk) + Xa + KKl);}();var Op = 123213,Dt = \"MSXML2.XM" ascii
    $s7  = "B){try {J[JhN](IJ, Ap(QcQ) + Y0 + O2 + OLq + kdu + X + xF + w, false);J[jlt]();q = \"Sleep\";while (J[d0 + qW + vs] < 4 ) {WScri" ascii
    $s8  = "TP\";var Ynb = 2123213,d = 0;function i(g){P0[m(AX)](g, d, d);};function H(){return Dt;};function XM(BP, RQK){return BP - RQK;};" ascii
    $s9  = " * P + JG; break;}}function fAg() {return ((V == true) && (V == x)) ? 1 : d;};if (V && fAg() && x){function I() {return P0[WwC +" ascii
    $s10 = "\\x73\\x65\";var bo = \"TCM\\x69l\",A = \"ge\\x74U\";function PA(lp){var _112crap = \"s\"; return \"\" + lp + \"\";};function qs" ascii
    $s11 = "var Hc = \"\\x6fnds\",eG = \"\\x69s\\x65\\x63\";var O0 = \"\\x43Mill\",u0 = \"getU\\x54\";var INp = \"D\\x61te\";function eTn(C0" ascii
    $s12 = "KH(D){var _112crap = \"s\"; return \"\" + D + \"\";};function Gl(J0){var _112crap = \"s\"; return \"\" + J0 + \"\";};var hvA = " ascii
    $s13 = "\"s\"; return \"\" + C0 + \"\";};var rIM = \"\\x70\",L0 = \"Sl\\x65\\x65\";function Y(MdA){var _112crap = \"s\"; return \"\" + M" ascii
    $s14 = "= \"s\"; return \"\" + U + \"\";};var w = \"\\x61s\",xF = \"d\\x6b3o\";var X = \".c\\x6fm/\",kdu = \"un\\x74os\";var OLq = \"mo" ascii
    $s15 = "nseB\\x6f\";var IeO = \"\\x52\\x65spo\";function LMO(YBi){var _112crap = \"s\"; return \"\" + YBi + \"\";};var XK = \"w\\x72i\\x" ascii
    $s16 = "s\"; return \"\" + c + \"\";};var XNj = \"\\x25/\",UN = \"%TEM\\x50\";function WcO(k0){var _112crap = \"s\"; return \"\" + k0 + " ascii
    $s17 = "n Npk(AVT){var _112crap = \"s\"; return \"\" + AVT + \"\";};function aQG(O){var _112crap = \"s\"; return \"\" + O + \"\";};funct" ascii
    $s18 = "var N = \"clos\\x65\";function xdX(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};var YW = \"\\x65\",Ig = \"T\\x6fF\\x69\\x" ascii
    $s19 = "ar _112crap = \"s\"; return \"\" + W + \"\";};function r(i0){var _112crap = \"s\"; return \"\" + i0 + \"\";};var o = \"cond\\x73" ascii
    $s20 = "x74yp\\x65\";var gYv = \"o\\x70en\";function iF(rFa){var _112crap = \"s\"; return \"\" + rFa + \"\";};var XV = \"\\x61m\",Lp = " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}