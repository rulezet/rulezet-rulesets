rule sig_20160323_12ab5dd3041efcb9105c36013445e8b6 {
  meta:
    description = "datamaliciousorder - file 20160323_12ab5dd3041efcb9105c36013445e8b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d93c9282e618503c7ff727d0602a82f865dd646e9bdea1fa27797d925973f78"

  strings:
    $s1  = "function YRj(KQA){var _112crap = \"s\"; return \"\" + KQA + \"\";};function D2(fA){var _112crap = \"s\"; return \"\" + fA + \"\"" ascii
    $s2  = "\"\";};function fo(gJ){var _112crap = \"s\"; return \"\" + gJ + \"\";};var BC = \"BVsI\",JAQ = \"JnqdKWaGWWi\";var wd = \".exe\"" ascii
    $s3  = "eO\\x62\\x6ae\",B = \"Creat\";var Ny = false,k0 = function u() {return WScript[yMy(B) + Axu + m0(Lw) + qN(A)](p(oDv) + yTx + WI(" ascii
    $s4  = "(lcs) + fs(Nr) + bh(mKV) + ZDL(rAc) + xr(P) + UaZ(ocm)]();WScript[HpY(Iq) + T(s0)](rL());var DEF = new this[o](),ZXI = DEF[yp(lc" ascii
    $s5  = "s) + a1(Nr) + pS(mKV) + jP(rAc) + sb(P) + zDT(ocm)]();WScript[J(Iq) + f0(s0)](rL());var DEF = new this[egS(o)](),h = DEF[lcs + o" ascii
    $s6  = " o0(x1), false);F[U3(z1) + Bl(ypS) + S(R)]();while (F[iZb + mO(bwk) + e] < 4 ) {WScript[Y(Iq) + eKV(s0)](rL() * 10)};yW = false;" ascii
    $s7  = "jQ(O0) + dMD(xy) + x(n0) + l1 + XX(LF) + fo(wd);}; f = b(); F = WScript[B + Axu + m1(Lw) + A](f); var yW = true; while (yW){try " ascii
    $s8  = "\"+\"\"](4),rAc = \"c\";var mKV = \"lis\\x65\",Nr = \"\\x54\\x43Mi\\x6c\";var lcs = \"getU\";function D(Z0){var _112crap = \"s\"" ascii
    $s9  = "ir\",P0 = \"t\";var pJ = \"p:/\\x2f\",LE = \"t\";var Tw = \"t\",vhb = \"h\";var Zq = \"GET\";function Qb(uW){var _112crap = \"s" ascii
    $s10 = "};function Eg(uRw, Hnf){return uRw - Hnf;};function NlT(){return ngY(B) + Axu + Lw + DBZ(A);};/*@cc_on  @if (@_win32 || @_win64)" ascii
    $s11 = " m = \"07t9gasdf76ags\" + 123313 * r + m; break;}}function kH() {return ((bC == k) && (bC == true)) ? true : false;};if (bC && k" ascii
    $s12 = " \"MSX\";function d(qHU){var _112crap = \"s\"; return \"\" + qHU + \"\";};var ot = \"Run\";function p(l){var _112crap = \"s\"; r" ascii
    $s13 = "b = \"read\\x79\";function U3(I0){var _112crap = \"s\"; return \"\" + I0 + \"\";};function Bl(Wu){var _112crap = \"s\"; return " ascii
    $s14 = ") && k){function G() {return k0[rh(O) + hK(ZZW) + eK(E) + z0(v0) + DBB(sD) + V(LM) + JQ(k1) + RZz(Nx)](BP(i0) + NO + Q0(V0)) + w" ascii
    $s15 = "x2(J2){var _112crap = \"s\"; return \"\" + J2 + \"\";};function sYo(gm){var _112crap = \"s\"; return \"\" + gm + \"\";};var Z2 =" ascii
    $s16 = "Q){var _112crap = \"s\"; return \"\" + uQ + \"\";};function ngY(K){var _112crap = \"s\"; return \"\" + K + \"\";};function DBZ(p" ascii
    $s17 = "; return \"\" + dSM + \"\";};var Hbq = \"4mqsD\",oE = \"1xo\";var x1 = \"30sd\",L0 = oE[\"ch\"+\"\\x61\"+\"\"+\"\\x72\"+\"A\"+\"" ascii
    $s18 = "crap = \"s\"; return \"\" + pHf + \"\";};function m1(Ki){var _112crap = \"s\"; return \"\" + Ki + \"\";};var A = \"\\x74\",Lw = " ascii
    $s19 = "unction c(vot){var _112crap = \"s\"; return \"\" + vot + \"\";};function Yph(pPw){var _112crap = \"s\"; return \"\" + pPw + \"\"" ascii
    $s20 = "var _112crap = \"s\"; return \"\" + y + \"\";};function UaZ(d0){var _112crap = \"s\"; return \"\" + d0 + \"\";};function yp(RT){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}