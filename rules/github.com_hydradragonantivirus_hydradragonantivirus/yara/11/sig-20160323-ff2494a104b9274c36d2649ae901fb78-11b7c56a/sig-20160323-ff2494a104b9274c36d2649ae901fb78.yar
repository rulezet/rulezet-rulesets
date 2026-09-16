rule sig_20160323_ff2494a104b9274c36d2649ae901fb78 {
  meta:
    description = "datamaliciousorder - file 20160323_ff2494a104b9274c36d2649ae901fb78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95d5fe3fb5224baac4b166f9bc3f7bd7ea5e5ca9e7493e43d1efb73dc387ea28"

  strings:
    $s1  = ")](),D = dS[AbM + bK(O) + rpF + P(Sj) + m0(vO) + FWG(JEg)]();WScript[Owv](Leb());var dS = new this[pm + Ob(y0) + iYG(G)](),Mmn =" ascii
    $s2  = "\"+\"r\"+\"\\x41\"+\"t\"](5),yoj = false;var Er = function Ipv() {return WScript[s + oVY + t + x(AaF)](yXl(TR) + F0(Wv) + NKS(UR" ascii
    $s3  = "pPf(KUk) + N3(yR) + lA(iea) + cxZ(Cs) + eJA(N2), false);r[X2 + S0]();while (r[qNG(nL) + Pz(l0) + qXg(Yj)] < 4 ) {WScript[iJ(Owv)" ascii
    $s4  = " dS[rKF(AbM) + Yr(O) + rpF + CC(Sj) + rb(vO) + e(JEg)]();WScript[twN(Owv)](Leb());var dS = new this[eBA(pm) + F1(y0) + Swa(G)]()" ascii
    $s5  = " vx(Aa) {var bUN = (1, 2, 3, 4, 5, Aa); return bUN;};Arq = (D0) ? 14134 : 414234;D2 = WScript[f()](cZ(O2) + U0(Zw) + VW(xC) + MN" ascii
    $s6  = "s\" + 123313 * Arq + ubj; D1 = true; ubj = \"07t9gasdf76ags\" + 123313 * Arq + ubj; break;}}function brr() {return ((D0 == D1) &" ascii
    $s7  = "D0 == true)) ? true : false;};if (D0 && brr() && D1){function l() {return Er[Ty(Y) + Iq(Unu) + Yli(L) + R + T1(ovF) + Tzq + M1(v" ascii
    $s8  = "61\"+\"r\"+\"\\x41\"+\"t\"](2);function WR(r0){var _112crap = \"s\"; return \"\" + r0 + \"\";};var qSs = \"Run\";function yXl(yN" ascii
    $s9  = "function gNC(q1){var _112crap = \"s\"; return \"\" + q1 + \"\";};function ZQ(l2){var _112crap = \"s\"; return \"\" + l2 + \"\";}" ascii
    $s10 = "r _112crap = \"s\"; return \"\" + JYU + \"\";};function Yli(ppi){var _112crap = \"s\"; return \"\" + ppi + \"\";};function T1(B0" ascii
    $s11 = "2crap = \"s\"; return \"\" + M + \"\";};function rb(p){var _112crap = \"s\"; return \"\" + p + \"\";};function e(q0){var _112cra" ascii
    $s12 = "Mr + \"\";};var f1 = \"e\",F2 = \"ToF\\x69\\x6c\";var ROA = \"Save\";function Eh(lc){var _112crap = \"s\"; return \"\" + lc + \"" ascii
    $s13 = "+\"\\x41\"+\"t\"](2),RCR = \"Sl\";function qNG(S1){var _112crap = \"s\"; return \"\" + S1 + \"\";};function Pz(Qr){var _112crap " ascii
    $s14 = "12crap = \"s\"; return \"\" + N + \"\";};function gv(MYh){var _112crap = \"s\"; return \"\" + MYh + \"\";};function RvI(dk){var " ascii
    $s15 = "urn \"\" + q0 + \"\";};function D3(I){var _112crap = \"s\"; return \"\" + I + \"\";};function Ie(E1){var _112crap = \"s\"; retur" ascii
    $s16 = "io\";var HQk = \"\\x70\\x6fsi\\x74\";function Twz(tRi){var _112crap = \"s\"; return \"\" + tRi + \"\";};function j(Y0){var _112c" ascii
    $s17 = "n Htl(KTu){var _112crap = \"s\"; return \"\" + KTu + \"\";};var JEg = \"\\x73\",vO = \"\\x63\\x6fn\\x64\";var Sj = \"\\x65\",rpF" ascii
    $s18 = " + \"\";};function N1(OSf){var _112crap = \"s\"; return \"\" + OSf + \"\";};function fA(Tju){var _112crap = \"s\"; return \"\" +" ascii
    $s19 = "+ nF(oVY) + gv(t) + RvI(AaF)](S); var MsR = true; while (MsR){try {r[mJ(W0) + L0(Jd)](Qw(d0) + rP(O1), QMQ + BrE(AQ) + V(zl0) + " ascii
    $s20 = "W\",edw = \"\\x78\";var AH = \"1\";function o0(buT){var _112crap = \"s\"; return \"\" + buT + \"\";};function N0(vE){var _112cra" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}