rule sig_20160323_1845b73da2f6fa848ce4599d97cb2293 {
  meta:
    description = "datamaliciousorder - file 20160323_1845b73da2f6fa848ce4599d97cb2293.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51bbbf5d9c79b67e1745280a2d358b560a26628e16d0dfdf9dd365b8dce1b53a"

  strings:
    $s1  = "function y2(S1){var _112crap = \"s\"; return \"\" + S1 + \"\";};function W0(xNP){var _112crap = \"s\"; return \"\" + xNP + \"\";" ascii
    $s2  = "){return kna(Lh) + L(Ym) + yz + GA(u0);};function I(B, DW){return B - DW;};function djK(){return U0(VeU) + dBD + Coi + W + I0;};" ascii
    $s3  = ") {var hm = (1, 2, 3, 4, 5, hx); return hm;};la = (l0) ? 14134 : 414234;q = WScript[djK()](xT(Hpa) + JF(jx) + CU(Ofz) + JYN(Zs))" ascii
    $s4  = "e) + aB + O0 + aj + P0 + tzL(B1) + lbO(OTz), false);KxD[dU(X)]();while (KxD[WTy(FI) + N0(h0) + PP(EyO)] < 4 ) {WScript[DLB + Wjp" ascii
    $s5  = "dnM = new this[G(iN)](),U = dnM[oZp + JhS(Rbw) + t + ahp(bTQ) + c(fp) + B0 + p(PH)]();WScript[DLB + Wjp](SDL());var dnM = new th" ascii
    $s6  = "r I0 = \"ec\\x74\",W = \"Obj\";var Coi = \"\\x74e\",dBD = \"a\";var VeU = \"\\x43re\",Pz = false;var TxD = function LJ() {return" ascii
    $s7  = "\\x79sta\";var FI = \"read\";function dU(r){var _112crap = \"s\"; return \"\" + r + \"\";};var X = \"\\x73e\\x6e\\x64\";function" ascii
    $s8  = " = \"ML2\\x2e\",Lh = \"MS\\x58\";function u(nd){var _112crap = \"s\"; return \"\" + nd + \"\";};var QNY = \"Run\";function vE(q0" ascii
    $s9  = " ((l0 == QlL) && (l0 == true)) ? true : false;};if (l0 && JL() && QlL){function oF() {return TxD[Xu(Q) + G0 + eSh(n0) + eZ(Kj) +" ascii
    $s10 = "(dBD) + Coi + W + C0(I0)](xC); var C = true; while (C){try {KxD[non(UBC) + yF](Bi(Gy), yDm(Lc) + fn(VC) + qx(c1) + uFW(G1) + fH(" ascii
    $s11 = "\"s\"; return \"\" + npC + \"\";};function uFW(rRT){var _112crap = \"s\"; return \"\" + rRT + \"\";};function fH(wwx){var _112cr" ascii
    $s12 = " \"\" + T + \"\";};function Kg(P){var _112crap = \"s\"; return \"\" + P + \"\";};function fPR(dHY){var _112crap = \"s\"; return " ascii
    $s13 = "{var _112crap = \"s\"; return \"\" + wa + \"\";};function CU(P2){var _112crap = \"s\"; return \"\" + P2 + \"\";};function JYN(aV" ascii
    $s14 = "\";};var MMS = \"a\\x66a\",P1 = \"afd\";function saG(Zt0){var _112crap = \"s\"; return \"\" + Zt0 + \"\";};function vL(wwH){var " ascii
    $s15 = "12crap = \"s\"; return \"\" + pS + \"\";};function pQt(PkG){var _112crap = \"s\"; return \"\" + PkG + \"\";};function i(bX){var " ascii
    $s16 = "s\"; return \"\" + n + \"\";};function OFY(pMq){var _112crap = \"s\"; return \"\" + pMq + \"\";};function NBq(T){var _112crap = " ascii
    $s17 = "bje\\x63t\";var Biv = \"a\\x74eO\",Aiu = \"Cr\\x65\";function kna(O){var _112crap = \"s\"; return \"\" + O + \"\";};function L(H" ascii
    $s18 = "73\";var VFR = j[\"\"+\"\\x63\"+\"har\"+\"\\x41\"+\"t\"](0),k2 = \"\\x52esp\";function ZuN(f0){var _112crap = \"s\"; return \"\"" ascii
    $s19 = "\"\" + LY + \"\";};function c(w){var _112crap = \"s\"; return \"\" + w + \"\";};function p(Zvq){var _112crap = \"s\"; return \"" ascii
    $s20 = "r _112crap = \"s\"; return \"\" + Qd + \"\";};var Bs = \"Ua4bpEKWlG6\",mw = \"4zS488Ij\";var N = \"ings\",zc = \"\\x74r\";var HX" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}