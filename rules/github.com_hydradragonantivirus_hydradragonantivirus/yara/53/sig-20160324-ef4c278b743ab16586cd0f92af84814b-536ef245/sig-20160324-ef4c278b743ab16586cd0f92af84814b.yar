rule sig_20160324_ef4c278b743ab16586cd0f92af84814b {
  meta:
    description = "datamaliciousorder - file 20160324_ef4c278b743ab16586cd0f92af84814b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f7b0bb48a5d2284ea0c0bd73615c7e6bea6e285f7f14f03693c12848dc2d11e"

  strings:
    $s1  = "var RB0 = \"c\\x6c\\x6f\\x73e\",fq = \"\\x65\";var PMD = \"oFi\\x6c\",Qa = \"S\\x61v\\x65\\x54\";var u0 = \"io\\x6e\",Y0 = \"pos" ascii
    $s2  = "Object\",nof = function m() {return WScript[Kz](eBb + NF + zS);}();var Km = 123213,ef = \"MSXML2.XMLHTTP\";var YO = 2123213,PS =" ascii
    $s3  = " = new this[h](),Qmb = L[HzM + cI + U0(GYA) + oA]();WScript[TqN](V());var L = new this[h](),I0 = L[HI(HzM) + VJn(cI) + XF(GYA) +" ascii
    $s4  = "G = (Ls, f + b, Rux + A(K), 2);};}function PB(BK) {var ZQy = (1, 2, 3, 4, 5, BK); return ZQy;};lh = WScript[Dg()](fAj + d(qXf) +" ascii
    $s5  = "v)](i1 + Gd(wR)) + aOY + rYj + N + zT;}; o = RB(); wma = WScript[Kz](o); var G = 1; while (G){try {wma[fv](ex, Q + t0(gp) + xiK " ascii
    $s6  = " o0(oA)]();WScript[TqN](V());var L = new this[h](),Poj = L[HzM + Lg(cI) + F(GYA) + oA]();var NqU = \"I\";NqU = D(I0, Qmb);var uD" ascii
    $s7  = "= \"get\\x55T\";var C = \"\\x44\\x61te\",TqN = \"Sl\\x65ep\";function U0(X){var _112crap = \"s\"; return \"\" + X + \"\";};funct" ascii
    $s8  = "function Czu(q){nof[fbY](q, PS, PS);};function RB(){return ef;};function D(kBv, J){return kBv - J;};function Dg(){return Kz;};/*" ascii
    $s9  = "eturn ((Wg == true) && (Wg == UrX)) ? 1 : PS;};if (Wg && eK() && UrX){function tRw() {return nof[uJn + oJm + IXj(i0) + z0 + Kg(z" ascii
    $s10 = "om\\x2f\\x6b\",DA = \"gn\\x2ec\";var xiK = \"de\\x73i\",gp = \"/\\x2f\\x68\\x75\";var Q = \"h\\x74\\x74p:\",ex = \"G\\x45T\";fun" ascii
    $s11 = "+ W(DA) + Od + nw + l, false);wma[s0]();wg = \"Sleep\";while (wma[l0 + iDe + Wqu] < 4 ) {WScript[wg](V() * 10)};G = PS;} catch(w" ascii
    $s12 = "\"s\"; return \"\" + IL + \"\";};function W(V0){var _112crap = \"s\"; return \"\" + V0 + \"\";};var l = \"\\x61\\x64\",nw = \"" ascii
    $s13 = "true; uD = \"07t9gasdf76ags\" + 123313 * NqU + uD; UrX = true; uD = \"07t9gasdf76ags\" + 123313 * NqU + uD; break;}}function eK(" ascii
    $s14 = "\";function Gd(c){var _112crap = \"s\"; return \"\" + c + \"\";};var wR = \"P\\x25/\",i1 = \"%\\x54EM\";function IXj(wi){var _11" ascii
    $s15 = " \"pOF\";uD = D(Poj, I0);return D(NqU, uD);}var Wg = false,UrX = false;for (var Vq = PS; Vq < V() * 1; Vq++){if (ac() != PS){Wg " ascii
    $s16 = "12crap = \"s\"; return \"\" + s + \"\";};function VJn(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};function XF(jo){var _112" ascii
    $s17 = "return \"\" + jo + \"\";};function o0(e){var _112crap = \"s\"; return \"\" + e + \"\";};function Lg(u){var _112crap = \"s\"; ret" ascii
    $s18 = "return \"\" + VvH + \"\";};var K = \"\\x61\",Rux = \"af\\x64\\x61f\";var b = \"\\x61\\x73d\\x66\",f = \"\\x66adf\";var Ls = \"as" ascii
    $s19 = "p = \"s\"; return \"\" + IE + \"\";};var C0 = \"a\\x6d\",qXf = \".S\\x74\\x72e\";var fAj = \"AD\\x4f\\x44B\";function A(VvH){var" ascii
    $s20 = " \"\";};function F(h0){var _112crap = \"s\"; return \"\" + h0 + \"\";};var oA = \"\\x6fnd\\x73\",GYA = \"li\\x73ec\";var cI = \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}