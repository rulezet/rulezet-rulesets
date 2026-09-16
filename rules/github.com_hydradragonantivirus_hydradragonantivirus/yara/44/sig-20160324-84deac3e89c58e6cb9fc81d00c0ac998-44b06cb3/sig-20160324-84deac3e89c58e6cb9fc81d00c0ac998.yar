rule sig_20160324_84deac3e89c58e6cb9fc81d00c0ac998 {
  meta:
    description = "datamaliciousorder - file 20160324_84deac3e89c58e6cb9fc81d00c0ac998.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a731691057088c63baeb87d75bfe72515f34df319d2e3b97d54002ca79bd4d24"

  strings:
    $s1  = "function vrA(sE){var _112crap = \"s\"; return \"\" + sE + \"\";};var mA = \"\\x63lose\";function hl0(il){var _112crap = \"s\"; r" ascii
    $s2  = "unction Le(){var Czu = new this[HA(pI)](),u = Czu[P(lfO) + DA(Avf) + i(NNI) + rsv + nJ(u2) + Dx(AT) + cBa]();WScript[D0 + O](lYg" ascii
    $s3  = " + t(FGY);}; iC = N(); KRH = WScript[PW(GHs) + NvT + Q + pg + eG](iC); var GdO = true; while (GdO){try {KRH[H1(ilY)](j0(gk), WFk" ascii
    $s4  = "rn WScript[GHs + E(NvT) + Q + m(pg) + l(eG)](M(fyl) + r(Tps) + n(d) + Qw(o));}();function Lc(hS){UZJ[y(a)](hS, 0, 0);};function " ascii
    $s5  = "\"c\"+\"\\x68\"+\"arAt\"](0);var D0 = \"Sl\\x65e\";function P(Cz){var _112crap = \"s\"; return \"\" + Cz + \"\";};function DA(A)" ascii
    $s6  = "\"; return \"\" + Ds + \"\";};var zCT = \"Gs6oR\",FGY = \"\\x78e\";var hpD = \"H\\x2e\\x65\",qDR = zCT[\"c\"+\"\\x68\"+\"arAt\"]" ascii
    $s7  = " \"\" + brI + \"\";};var PvE = \"Eekq\",rf = PvE[\"c\"+\"\\x68\"+\"arAt\"](1);var Z0 = \"t\",ghW = \"ta\";var EEe = \"dys\",yZ =" ascii
    $s8  = "x65a\";var PF = s1[\"c\"+\"\\x68\"+\"arAt\"](3),sC = \"ADOD\\x42\";function w2(OuM){var _112crap = \"s\"; return \"\" + OuM + \"" ascii
    $s9  = "n \"\" + trG + \"\";};var gk = \"GET\";function H1(VwP){var _112crap = \"s\"; return \"\" + VwP + \"\";};function LE(m0){var _11" ascii
    $s10 = "TJ){var _112crap = \"s\"; return \"\" + PTJ + \"\";};var yV = \"cHGx8ajrS\",dEM = \"sdfa\";var q1 = yV[\"c\"+\"\\x68\"+\"arAt\"]" ascii
    $s11 = "+\"\\x68\"+\"arAt\"](3);var z1 = w3[\"c\"+\"\\x68\"+\"arAt\"](2),gM = \"ope\\x6e\";function dw0(ph){var _112crap = \"s\"; return" ascii
    $s12 = "+\"\\x68\"+\"arAt\"](2);var NNI = \"il\",Avf = \"\\x43M\";var lfO = \"g\\x65tU\\x54\";function HA(L){var _112crap = \"s\"; retur" ascii
    $s13 = "c\"+\"\\x68\"+\"arAt\"](1);var ZzM = \"\\x52espo\";function k2(US){var _112crap = \"s\"; return \"\" + US + \"\";};function v2(R" ascii
    $s14 = "3\",Tps = u0[\"c\"+\"\\x68\"+\"arAt\"](5);var fyl = \"WSc\";function E(BYo){var _112crap = \"s\"; return \"\" + BYo + \"\";};fun" ascii
    $s15 = "(X){var _112crap = \"s\"; return \"\" + X + \"\";};var s1 = \"BCL.\",b1 = \"WThHimzrFg\";var dnA = b1[\"c\"+\"\\x68\"+\"arAt\"](" ascii
    $s16 = "N(){return u1(ZL) + kWa(l0) + K(wH) + MK(kt);};function aJ(fur, chT){return fur - chT;};function ER(){return GHs + NvT + h(Q) + " ascii
    $s17 = " = \"2.\\x58\",ZL = \"M\\x53XML\";function y(E1){var _112crap = \"s\"; return \"\" + E1 + \"\";};var a = \"Run\";function M(yTW)" ascii
    $s18 = ") + Z0 + rf] < 4 ) {WScript[d1(D0) + k(O)](lYg() * 10)};GdO = false;} catch(pip){GdO = (nr(q1) + k1(dEM), UUW(OAk) + wG(b0) + S(" ascii
    $s19 = "());var Czu = new this[vca(pI)](),SX = Czu[csS(lfO) + Zp(Avf) + ZoX(NNI) + l1(rsv) + u2 + ihE(AT) + GT(cBa)]();WScript[Ez(D0) + " ascii
    $s20 = "= \"\\x61f\",SI = \"sharm\";var zvT = \"tp://\",omW = \"t\";var WFk = NQ[\"c\"+\"\\x68\"+\"arAt\"](5);function j0(trG){var _112c" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}