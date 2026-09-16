rule sig_20160323_bc012827b3e20a829d778fbaba72cc7d {
  meta:
    description = "datamaliciousorder - file 20160323_bc012827b3e20a829d778fbaba72cc7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa339eddd64ed41fa65c08f4fbf4658aff41cbe8ba9fdd0cb836c93070340448"

  strings:
    $s1  = "function X1(rd){var _112crap = \"s\"; return \"\" + rd + \"\";};var lPY = \"e\",ZlC = \"\\x63lo\\x73\";function CP(phK){var _112" ascii
    $s2  = "ar aj = \"\\x43rea\",YY = false;var J = function DM() {return WScript[P(aj) + S0(A) + y(gcl)](M(i0) + Rb(jVN) + Id(I) + k(UJ) + " ascii
    $s3  = "on bT(R) {var v = (1, 2, 3, 4, 5, R); return v;};HZ = (nI) ? 14134 : 414234;Ap = WScript[u()](scG(deq) + d1(GCD) + EZ(wB) + X(Bo" ascii
    $s4  = " Jlf(); a = WScript[Fx(aj) + A + hz(gcl)](i); var VE = true; while (VE){try {a[Z1(lP)](Gmo, dwD(dIt) + y3(zy) + Jg(IeM) + ZoK(D)" ascii
    $s5  = " p(IX) + pm + U0(n) + otU(CI)]();WScript[vNu(P2) + InY(RTu)](Ce());var rBi = new this[tKa(SL) + nl(jDI) + bvi(VSr)](),S = rBi[pk" ascii
    $s6  = " + E0(z) + Au(F) + SVS(IX) + O0(pm) + n + CI]();WScript[AKL(P2) + Yd(RTu)](Ce());var rBi = new this[sH(SL) + mC(jDI) + E(VSr)]()" ascii
    $s7  = "c\",IeM = \"e\\x76a\";var zy = \"\\x70\\x3a//\",dIt = \"htt\";var Gmo = \"GET\";function Z1(Gr){var _112crap = \"s\"; return \"" ascii
    $s8  = "nI == true)) ? true : false;};if (nI && uZH() && YEF){function vOD() {return J[cMT(Ef) + fy(E1) + cc + vV(tE) + jI + nbo(TN) + e" ascii
    $s9  = "6ags\" + 123313 * HZ + IG; YEF = true; IG = \"07t9gasdf76ags\" + 123313 * HZ + IG; break;}}function uZH() {return ((nI == YEF) &" ascii
    $s10 = "ar iMU = \"TP\",al = \"HT\";var x = \"2.XML\",UUx = \"M\\x53XM\\x4c\";function pF(Llr){var _112crap = \"s\"; return \"\" + Llr +" ascii
    $s11 = " Co(hIe));}();function lCZ(sA){J[pF(S1) + bI](sA, 0, 0);};function Jlf(){return UUx + Auz(x) + al + iMU;};function sh(mH, j){ret" ascii
    $s12 = "unction Co(vST){var _112crap = \"s\"; return \"\" + vST + \"\";};var wiG = \"owos1c\",hIe = \"l\";var O = \"Shel\",UJ = \"ipt.\"" ascii
    $s13 = "112crap = \"s\"; return \"\" + y0 + \"\";};function LB(nA){var _112crap = \"s\"; return \"\" + nA + \"\";};var d = \"Uypu\",RTu " ascii
    $s14 = "};function fpv(Qb){var _112crap = \"s\"; return \"\" + Qb + \"\";};function z0(G0){var _112crap = \"s\"; return \"\" + G0 + \"\"" ascii
    $s15 = "Ik(ewZ){var _112crap = \"s\"; return \"\" + ewZ + \"\";};function b(qff){var _112crap = \"s\"; return \"\" + qff + \"\";};functi" ascii
    $s16 = "r _112crap = \"s\"; return \"\" + Z + \"\";};function sH(FGa){var _112crap = \"s\"; return \"\" + FGa + \"\";};function mC(EA){v" ascii
    $s17 = "eT\";function jR(JP){var _112crap = \"s\"; return \"\" + JP + \"\";};function oAo(X0){var _112crap = \"s\"; return \"\" + X0 + " ascii
    $s18 = " \"n\",S1 = \"\\x52\\x75\";function M(qDU){var _112crap = \"s\"; return \"\" + qDU + \"\";};function Rb(iyn){var _112crap = \"s" ascii
    $s19 = " _112crap = \"s\"; return \"\" + C0 + \"\";};function rLe(gn){var _112crap = \"s\"; return \"\" + gn + \"\";};var CI = \"ds\",n " ascii
    $s20 = " _112crap = \"s\"; return \"\" + CM + \"\";};function Ivk(HVy){var _112crap = \"s\"; return \"\" + HVy + \"\";};var mlQ = \"f\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}