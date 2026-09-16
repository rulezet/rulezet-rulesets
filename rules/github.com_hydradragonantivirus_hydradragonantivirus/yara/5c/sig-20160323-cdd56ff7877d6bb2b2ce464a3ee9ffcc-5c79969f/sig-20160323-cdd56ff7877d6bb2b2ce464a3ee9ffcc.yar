rule sig_20160323_cdd56ff7877d6bb2b2ce464a3ee9ffcc {
  meta:
    description = "datamaliciousorder - file 20160323_cdd56ff7877d6bb2b2ce464a3ee9ffcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2dcf531300d733d07fe1f26c7d005126b36fb925ad54861264bb10e968e56f5e"

  strings:
    $s1  = "var J2 = \"close\";function x3(l2){var _112crap = \"s\"; return \"\" + l2 + \"\";};function S1(Fo){var _112crap = \"s\"; return " ascii
    $s2  = "Ms(AH)]();WScript[M(rOG) + r2(KBx) + G0(u0)](bN());var DR = new this[L + dAo + uWh + Z](),b = DR[O(XIb) + Qp(wWa) + IDz(P) + PcR" ascii
    $s3  = " yo(zr) + Bfn + oX(Qb) + F0, false);D[xgu(m3) + tN(My)]();while (D[MBj + Z0(aPb) + ri] < 4 ) {WScript[lN(rOG) + KBx + dp(u0)](bN" ascii
    $s4  = "(LO) + kVQ(R) + nt(Ip) + cU + AH]();WScript[o0(rOG) + aG(KBx) + S0(u0)](bN());var DR = new this[ksk(L) + dAo + uWh + B3(Z)](),B1" ascii
    $s5  = "var uzF = (1, 2, 3, 4, 5, jQ); return uzF;};OY = (wLJ) ? 14134 : 414234;m = WScript[Hf()](ko + dsl(ZOF) + vD(Uyb) + PI(ilP));Wzz" ascii
    $s6  = "x0(K) + Of + Pm + Bp(eCD) + iqx + oFv(iX) + I(lrF);};function QA(Tn, Y){return Tn - Y;};function Hf(){return z(r) + qVJ + r0(jW)" ascii
    $s7  = "J == f) && (wLJ == true)) ? true : false;};if (wLJ && B() && f){function MpD() {return PeW[yN + KBR(tcs) + o2 + FtZ(e0) + aex(xj" ascii
    $s8  = "Of = z0[\"c\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](3);var K = \"\\x4dS\";function s(gBe){var _112crap = \"s\"; return \"\" + gBe + " ascii
    $s9  = "f\\x6ee\",mL = \"\\x61ra.c\";var dTi = \"\\x66\\x69ha\",p0 = \"://\";var g = \"http\";function xye(db){var _112crap = \"s\"; ret" ascii
    $s10 = "3on\";var Ip = \"e\",R = \"is\";var LO = \"CMill\",P = \"\\x54\";var wWa = \"U\",XIb = \"get\";function K0(vB){var _112crap = \"" ascii
    $s11 = "\"s\"; return \"\" + dTv + \"\";};function aex(Iw){var _112crap = \"s\"; return \"\" + Iw + \"\";};function KO(j0){var _112crap " ascii
    $s12 = "var _112crap = \"s\"; return \"\" + m0 + \"\";};function z(Ml){var _112crap = \"s\"; return \"\" + Ml + \"\";};function r0(mRb){" ascii
    $s13 = ";function xgu(Q){var _112crap = \"s\"; return \"\" + Q + \"\";};function tN(d){var _112crap = \"s\"; return \"\" + d + \"\";};va" ascii
    $s14 = "_112crap = \"s\"; return \"\" + xVn + \"\";};function Qe(oO){var _112crap = \"s\"; return \"\" + oO + \"\";};var xE = \"nTHr\",R" ascii
    $s15 = "G2[\"c\"+\"\\x68\"+\"ar\"+\"\\x41\"+\"t\"](2);var v0 = \"\\x74\",b3 = \"Crea\";function bak(z1){var _112crap = \"s\"; return \"" ascii
    $s16 = "= \"CMi\";var FI = \"g\\x65tUT\",LWm = \"D\\x61te\";function M(GI){var _112crap = \"s\"; return \"\" + GI + \"\";};function r2(H" ascii
    $s17 = "unction ksk(MRM){var _112crap = \"s\"; return \"\" + MRM + \"\";};function B3(ZSS){var _112crap = \"s\"; return \"\" + ZSS + \"" ascii
    $s18 = " \"\" + GJz + \"\";};function PI(jQZ){var _112crap = \"s\"; return \"\" + jQZ + \"\";};var UpD = \"ABAjwC\",ilP = \"\\x72ea\\x6d" ascii
    $s19 = "cPs(){var DR = new this[K0(L) + dAo + c(uWh) + Jgb(Z)](),ilG = DR[XIb + XPb(wWa) + U(P) + b0(LO) + ymK(R) + vAM(Ip) + ha(cU) + G" ascii
    $s20 = "\"; return \"\" + ji + \"\";};function U(nwx){var _112crap = \"s\"; return \"\" + nwx + \"\";};function b0(G){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}