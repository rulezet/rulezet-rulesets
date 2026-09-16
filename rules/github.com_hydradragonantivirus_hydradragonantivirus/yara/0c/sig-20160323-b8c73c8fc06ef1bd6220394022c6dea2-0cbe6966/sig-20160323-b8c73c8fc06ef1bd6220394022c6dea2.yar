rule sig_20160323_b8c73c8fc06ef1bd6220394022c6dea2 {
  meta:
    description = "datamaliciousorder - file 20160323_b8c73c8fc06ef1bd6220394022c6dea2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d78c7a6021176ffd7ae8e1690645670be17b28946a227f64fb759d4f2713855"

  strings:
    $s1  = "function k1(CwG){var _112crap = \"s\"; return \"\" + CwG + \"\";};var Daw = \"o\\x73e\",Q4 = \"c\\x6c\";function ojG(E1){var _11" ascii
    $s2  = "= function IN() {return WScript[c(Yn) + W + eh(PU)](tX(TSG) + Of(pS) + Bt + lg(Tdk) + nZ(FK));}();function fQI(TvC){NW[BR(H1) + " ascii
    $s3  = "qi());var Un = new this[J(t0)](),hKQ = Un[kwV(fvD) + adI + X2(o) + L + Td]();WScript[u(oQ) + K](qi());var Un = new this[X1(t0)](" ascii
    $s4  = "se);NS[ZF(Dr) + uO(itf) + Rb(SmG)]();while (NS[aL(is) + RSw(I) + l(x2) + Esl] < 4 ) {WScript[pz(oQ) + eyN(K)](qi() * 10)};v = fa" ascii
    $s5  = "b) {var aB = (1, 2, 3, 4, 5, db); return aB;};H = (a0) ? 14134 : 414234;f = WScript[Zh()](Ds + LE + P2 + F3(UtZ) + Cg(Plw) + ak(" ascii
    $s6  = "n) + J0 + Ge(XB)) + rPB(ryt) + UgJ + GBR(vFL) + yP(MQ);}; R = Hd(); NS = WScript[Vq(Yn) + W + JLe(PU)](R); var v = true; while (" ascii
    $s7  = "var H = 0,unm = 0;function X0(){var Un = new this[gA(t0)](),xCt = Un[HZ(fvD) + adI + yra(o) + L + x(Td)]();WScript[oQ + OhQ(K)](" ascii
    $s8  = " = \"n\\x64s\",L = \"iseco\";var o = \"ll\",adI = \"T\\x43\\x4di\";var fvD = \"getU\";function gA(Fz){var _112crap = \"s\"; retu" ascii
    $s9  = "z](TvC, 0, 0);};function Hd(){return sJo(Cc) + v0(zOk) + xX + qdf(XD) + PJ(DZ) + zt(Luz);};function vg(k, V){return k - V;};func" ascii
    $s10 = ")) ? true : false;};if (a0 && X() && FUw){function qWz() {return NW[dMu + nat(n0) + lI(j) + EO(eae) + A0 + A1(e) + u1(U0)](H2(xT" ascii
    $s11 = "23313 * H + unm; FUw = true; unm = \"07t9gasdf76ags\" + 123313 * H + unm; break;}}function X() {return ((a0 == FUw) && (a0 == tr" ascii
    $s12 = "\\x44ate\",ob = \"t\";var P = \"b\\x6aec\",k0 = \"\\x74eO\";var sOf = \"Cre\\x61\";function sJo(t){var _112crap = \"s\"; return " ascii
    $s13 = "\\x74\"+\"\"](3);function Ltx(XMB){var _112crap = \"s\"; return \"\" + XMB + \"\";};function x0(vwI){var _112crap = \"s\"; retur" ascii
    $s14 = ",GCy = \"p\";function Eol(Q3){var _112crap = \"s\"; return \"\" + Q3 + \"\";};function Sq(Xe){var _112crap = \"s\"; return \"\" " ascii
    $s15 = "nction GY(v1){var _112crap = \"s\"; return \"\" + v1 + \"\";};var uE = \"kfyEaJLPPZ\",o0 = \"f\";var ui = \"df\\x61sd\",i = uE[" ascii
    $s16 = "\"\" + ibO + \"\";};function nZ(n){var _112crap = \"s\"; return \"\" + n + \"\";};var f0 = \"cUl\",g = \"E0ZJlX\";var FK = g[\"c" ascii
    $s17 = "+\"\"](4);var w1 = \"\\x66\";function VG(Q2){var _112crap = \"s\"; return \"\" + Q2 + \"\";};function vhB(FC){var _112crap = \"s" ascii
    $s18 = "= F[\"charA\"+\"\\x74\"+\"\"](4);var oQ = \"S\\x6c\\x65e\";function HZ(hf){var _112crap = \"s\"; return \"\" + hf + \"\";};funct" ascii
    $s19 = "= \"s\"; return \"\" + w0 + \"\";};function X2(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};function r(nD){var _112crap =" ascii
    $s20 = "_112crap = \"s\"; return \"\" + Ro + \"\";};var IF = \"6OeXyFAk\",xUe = IF[\"charA\"+\"\\x74\"+\"\"](2);var RDt = \"yp\",Sg = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}