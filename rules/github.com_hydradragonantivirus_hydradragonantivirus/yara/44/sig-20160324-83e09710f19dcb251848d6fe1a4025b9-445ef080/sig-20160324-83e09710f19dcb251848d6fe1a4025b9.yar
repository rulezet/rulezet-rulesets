rule sig_20160324_83e09710f19dcb251848d6fe1a4025b9 {
  meta:
    description = "datamaliciousorder - file 20160324_83e09710f19dcb251848d6fe1a4025b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86ec0c75acc3af57b8cee3e425655095e133e9894bc92f4b19ec7462d3d4713f"

  strings:
    $s1  = "var Z0 = \"\\x63lo\\x73e\",SlV = \"\\x65\";var jz = \"o\\x46il\",cK = \"\\x53aveT\";function El(W1){var _112crap = \"s\"; return" ascii
    $s2  = "i() {return WScript[v](UUp(v0) + OK(M) + Hj);}();var V0 = 123213,OT = \"MSXML2.XMLHTTP\";var OH = 2123213,xi = 0;function krE(Dr" ascii
    $s3  = "hdl + eEd, Inm + q, 2);};}function cka(SZ) {var XE = (1, 2, 3, 4, 5, SZ); return XE;};G = WScript[Z()](K0(Qp) + PZQ(U) + hR(wwJ)" ascii
    $s4  = " F[ic(i) + Lhj + L(nd) + O0]();WScript[Ui + jPh(Nm)](Efn());var F = new this[O](),Cv = F[i + Lhj + HYZ(nd) + O0]();WScript[Ui + " ascii
    $s5  = "};function P(roV){var _112crap = \"s\"; return \"\" + roV + \"\";};var O0 = \"\\x6eds\",nd = \"i\\x73eco\";var Lhj = \"CMi\\x6c" ascii
    $s6  = " + 123313 * BM + Uun; j = true; Uun = \"07t9gasdf76ags\" + 123313 * BM + Uun; break;}}function zHi() {return ((gxV == true) && (" ascii
    $s7  = "V == j)) ? 1 : xi;};if (gxV && zHi() && j){function mJ() {return mrH[n0 + ejp + exQ + zl + DxZ + drG](F0(HXE) + m) + vrj(MyV) + " ascii
    $s8  = "lfK(O1) + sh + ntP;}; im = KcA(); Jcf = WScript[v](im); var Hw = 1; while (Hw){try {Jcf[Lq](K, wk + l(uq) + bDO + YhJ + L0 + j0," ascii
    $s9  = " false);Jcf[m0]();I = \"Sleep\";while (Jcf[kj(fs) + M0] < 4 ) {WScript[I](Efn() * 10)};Hw = xi;} catch(W){Hw = (H(lE) + tdU(Rgd)" ascii
    $s10 = "\"ht\\x74\\x70:\";var K = \"\\x47\\x45T\";function ulb(lRN){var _112crap = \"s\"; return \"\" + lRN + \"\";};var Lq = \"ope\\x6e" ascii
    $s11 = "seB\";var KN = \"\\x52e\\x73p\";function F1(qa){var _112crap = \"s\"; return \"\" + qa + \"\";};var fm = \"\\x65\",B2 = \"\\x77r" ascii
    $s12 = "rn T(BM, Uun);}var gxV = false,j = false;for (var r = xi; r < Efn() * 1; r++){if (UM() != xi){gxV = true; Uun = \"07t9gasdf76ags" ascii
    $s13 = "4fDB\",q = \"\\x61\";var Inm = \"a\\x66\\x64a\\x66\",eEd = \"as\\x64f\";var hdl = \"fa\\x64f\";function H(Ut){var _112crap = \"s" ascii
    $s14 = "turn \"\" + Td + \"\";};function hR(ke){var _112crap = \"s\"; return \"\" + ke + \"\";};var wwJ = \"\\x61m\",U = \"\\x2eStre\";v" ascii
    $s15 = " \"\\x74yp\\x65\",l0 = \"op\\x65n\";function K0(kTO){var _112crap = \"s\"; return \"\" + kTO + \"\";};function PZQ(Td){var _112c" ascii
    $s16 = ";var fsx = \"\\x69on\",fuY = \"\\x70osit\";function i1(YYR){var _112crap = \"s\"; return \"\" + YYR + \"\";};var s = \"od\\x79\"" ascii
    $s17 = "jPh(bJ){var _112crap = \"s\"; return \"\" + bJ + \"\";};var Nm = \"\\x70\",Ui = \"Sl\\x65\\x65\";function ic(Fo){var _112crap = " ascii
    $s18 = "var Z0 = \"\\x63lo\\x73e\",SlV = \"\\x65\";var jz = \"o\\x46il\",cK = \"\\x53aveT\";function El(W1){var _112crap = \"s\"; return" ascii
    $s19 = "mrH[y](Dr, xi, xi);};function KcA(){return OT;};function T(n, MX){return n - MX;};function Z(){return v;};/*@cc_on  @if (@_win32" ascii
    $s20 = "p = \"s\"; return \"\" + B0 + \"\";};function OK(R){var _112crap = \"s\"; return \"\" + R + \"\";};var Hj = \"he\\x6c\\x6c\",M =" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}