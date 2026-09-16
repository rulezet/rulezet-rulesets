rule sig_20160323_56fbf73298a82c0f2ba0eacb3ca0cb99 {
  meta:
    description = "datamaliciousorder - file 20160323_56fbf73298a82c0f2ba0eacb3ca0cb99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc8f5ab654222476cc90974cfda7d8d7e96403aafb9024fe1a2e2c2a97c84892"

  strings:
    $s1  = "function h0(CTm){var _112crap = \"s\"; return \"\" + CTm + \"\";};var g3 = \"o\\x73e\",F2 = \"\\x63\\x6c\";function Gjv(Z0){var " ascii
    $s2  = "= \"\\x74e\";var E = \"ea\",DUf = \"C\\x72\";var PxN = false,PjY = function BXJ() {return WScript[JJ(DUf) + b(E) + DA(FWI) + H0(" ascii
    $s3  = ";var O = new this[nBe(VVi) + A + V(aN)](),dRf = O[r(Px) + EMn(Q) + wG(Hk) + le(f) + r0(D) + p2(b0) + Zn(rE)]();WScript[p3(YjJ)](" ascii
    $s4  = "ar idN = (1, 2, 3, 4, 5, rLj); return idN;};G0 = (y) ? 14134 : 414234;MrA = WScript[Hlw()](RN(C2) + odW(U0) + hP(Dmj));w = MrA;P" ascii
    $s5  = "tion rX(){var O = new this[VVi + Ma(A) + aN](),Az = O[zdJ(Px) + K(Q) + Hk + pBj(f) + MzR(D) + b0 + rE]();WScript[f1(YjJ)](JcV())" ascii
    $s6  = "/d\\x69e\";var Sr = \"t\\x74p:\",eP = J0[\"char\"+\"\\x41\"+\"\"+\"\\x74\"+\"\"](3);function hA(s0){var _112crap = \"s\"; return" ascii
    $s7  = ") + UB + T0(I2) + F0(HPo) + RbC(wY), false);Lbh[GW(ik) + L(P0)]();while (Lbh[hsa(CSj) + UCJ + VQo(B1)] < 4 ) {WScript[Hk0(YjJ)](" ascii
    $s8  = "n G1(PEf) + ywe(p1) + WJY(Yg) + Z(v0);};function zT(C, ZG){return C - ZG;};function Hlw(){return ZR(DUf) + Erg(E) + FWI + c + rq" ascii
    $s9  = "on zv() {return ((y == sPE) && (y == true)) ? true : false;};if (y && zv() && sPE){function q() {return PjY[Xv(Am) + P(Ps) + B0(" ascii
    $s10 = "\\x53\";function JJ(hh){var _112crap = \"s\"; return \"\" + hh + \"\";};function b(KwH){var _112crap = \"s\"; return \"\" + KwH " ascii
    $s11 = "\\x65O\";var d = \"\\x43r\\x65a\";function NI(XJA){var _112crap = \"s\"; return \"\" + XJA + \"\";};function I1(j2){var _112crap" ascii
    $s12 = ";};function I(B){var _112crap = \"s\"; return \"\" + B + \"\";};function u(p){var _112crap = \"s\"; return \"\" + p + \"\";};var" ascii
    $s13 = "UTC\\x4d\";var Px = \"ge\";function Ma(ok){var _112crap = \"s\"; return \"\" + ok + \"\";};function nBe(Yb){var _112crap = \"s\"" ascii
    $s14 = "VP + \"\";};function Z(ICI){var _112crap = \"s\"; return \"\" + ICI + \"\";};var v0 = \"HTT\\x50\",Yg = \"\\x2e\\x58\\x4dL\";var" ascii
    $s15 = " _112crap = \"s\"; return \"\" + GtF + \"\";};function ihF(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};function yCO(eg){" ascii
    $s16 = "{var _112crap = \"s\"; return \"\" + Q0 + \"\";};function bN(dCH){var _112crap = \"s\"; return \"\" + dCH + \"\";};var vm = \"" ascii
    $s17 = "\";};function B0(IT){var _112crap = \"s\"; return \"\" + IT + \"\";};function nE(gG){var _112crap = \"s\"; return \"\" + gG + \"" ascii
    $s18 = "n r(j0){var _112crap = \"s\"; return \"\" + j0 + \"\";};function EMn(CSU){var _112crap = \"s\"; return \"\" + CSU + \"\";};funct" ascii
    $s19 = "\"; return \"\" + Z0 + \"\";};function cTa(MA){var _112crap = \"s\"; return \"\" + MA + \"\";};function KaU(G4){var _112crap = " ascii
    $s20 = "(fn){var _112crap = \"s\"; return \"\" + fn + \"\";};function hP(aON){var _112crap = \"s\"; return \"\" + aON + \"\";};var Dmj =" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}