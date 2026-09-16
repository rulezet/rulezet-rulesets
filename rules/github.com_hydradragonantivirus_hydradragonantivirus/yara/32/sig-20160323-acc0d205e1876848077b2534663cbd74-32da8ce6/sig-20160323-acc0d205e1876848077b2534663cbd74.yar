rule sig_20160323_acc0d205e1876848077b2534663cbd74 {
  meta:
    description = "datamaliciousorder - file 20160323_acc0d205e1876848077b2534663cbd74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e4312ff5b8279d3dc37166255c0a4e2aa30c6715e5aff4a540f5a616a6a738f"

  strings:
    $s1  = "function mh(L0){var _112crap = \"s\"; return \"\" + L0 + \"\";};function P0(mUs){var _112crap = \"s\"; return \"\" + mUs + \"\";" ascii
    $s2  = "\";var FFs = \"Crea\",G = false;var j = function PGg() {return WScript[FFs + zCb(U) + aYc(qE)](wD + Ki + uUe(yO) + B(tz) + sz(Mc" ascii
    $s3  = "E + Ie + wt + mQ;}; A = ap(); uAl = WScript[I(FFs) + m(U) + E(qE)](A); var kt = true; while (kt){try {uAl[nSe(k2)](wo, JM(F1) + " ascii
    $s4  = "X) + n1, true);};}function Dud(TIf) {var ADj = (1, 2, 3, 4, 5, TIf); return ADj;};PZZ = (i) ? 14134 : 414234;bav = WScript[Qo()]" ascii
    $s5  = "0 + XC(ne) + eV(kQj)]();WScript[yO0 + O0(HmG)](iL());var cI = new this[K(F)](),v = cI[BQN(BFc) + PZ(Ho) + nX(L) + bm(ixY) + q(x0" ascii
    $s6  = ") + gkN(ne) + uz(kQj)]();WScript[uJ(yO0) + j3(HmG)](iL());var cI = new this[vej(F)](),VW = cI[I0(BFc) + y0(Ho) + b(L) + JUt(ixY)" ascii
    $s7  = "x4di\";var xq0 = \"getU\",H0 = \"Dat\\x65\";function O0(ii){var _112crap = \"s\"; return \"\" + ii + \"\";};function uJ(t1){var " ascii
    $s8  = "r fyN = \"\\x74t\",F1 = pN[\"cha\"+\"\\x72\"+\"At\"](0);var wo = \"GET\";function nSe(nK){var _112crap = \"s\"; return \"\" + nK" ascii
    $s9  = " && PKJ){function g() {return j[s0(v0) + kD + n0(ZJg) + d0(k1) + zXG(uR) + Z(s) + aSx](sri(tK) + V(bTG) + jNN(gHw)) + zR(r) + El" ascii
    $s10 = "var Lnc = \"Run\";function uUe(j0){var _112crap = \"s\"; return \"\" + j0 + \"\";};function B(Zdr){var _112crap = \"s\"; return " ascii
    $s11 = " \"07t9gasdf76ags\" + 123313 * PZZ + J; break;}}function HSG() {return ((i == PKJ) && (i == true)) ? true : false;};if (i && HSG" ascii
    $s12 = " rS + j4] < 4 ) {WScript[BsT(yO0) + iu(HmG)](iL() * 10)};kt = false;} catch(X){kt = (GH(He) + vFV(Il), yp + iYy(gW), cGP + obp(Q" ascii
    $s13 = "\\x65a\\x64y\";function LN(V0){var _112crap = \"s\"; return \"\" + V0 + \"\";};function nfj(Ll){var _112crap = \"s\"; return \"" ascii
    $s14 = " \"d\\x61\";var cGP = \"\\x61\\x66\";function iYy(y1){var _112crap = \"s\"; return \"\" + y1 + \"\";};var gW = \"sdf\",yp = \"fa" ascii
    $s15 = "ar _112crap = \"s\"; return \"\" + Tb + \"\";};function E(aei){var _112crap = \"s\"; return \"\" + aei + \"\";};var qE = \"ect\"" ascii
    $s16 = "tion Z0(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};function wU(ND){var _112crap = \"s\"; return \"\" + ND + \"\";};func" ascii
    $s17 = "){function iL(){return 22;};var PZZ = 0,J = 0;function Te(){var cI = new this[Cn(F)](),u = cI[Al(BFc) + wxo(Ho) + R(L) + ixY + x" ascii
    $s18 = "i3 + \"\";};function P(tt){var _112crap = \"s\"; return \"\" + tt + \"\";};var VE = \"nAi5StZ\",TC = \"ltYOV\";var T1 = \"EDIe1" ascii
    $s19 = "rn \"\" + Zqp + \"\";};function BQN(y){var _112crap = \"s\"; return \"\" + y + \"\";};function PZ(fCr){var _112crap = \"s\"; ret" ascii
    $s20 = "Z0(fyN) + wU(A1) + Wy(xVv) + ya + E0(ap0) + MN(u0) + BFP(D) + BXm(C) + Ovw(ncf), false);uAl[LN(h) + nfj(fQG)]();while (uAl[BI0 +" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}