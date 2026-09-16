rule sig_20160323_f2505c2f733175fd15763216b70d549c {
  meta:
    description = "datamaliciousorder - file 20160323_f2505c2f733175fd15763216b70d549c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83ff103c305c4b48d7d2c0c139df95cd3ca2066011397681b25e75b565360ed6"

  strings:
    $s1  = "function q0(y0){var _112crap = \"s\"; return \"\" + y0 + \"\";};function mxW(KT0){var _112crap = \"s\"; return \"\" + KT0 + \"\"" ascii
    $s2  = "R(Ucq) + KT(a) + b(hKi) + FSP(Vnk) + SVQ(pdw) + Yfg(hsj) + gyl]();WScript[db + LT(E0)](UW());var K = new this[ZJ(pGZ) + Lc(r1)](" ascii
    $s3  = "),cCV = K[Lg(Ja) + Ucq + bd(a) + W0(hKi) + Vnk + pdw + hsj + o(gyl)]();WScript[Ms(db) + FL(E0)](UW());var K = new this[pGZ + HhN" ascii
    $s4  = " false;var g = function d() {return WScript[dYW + bV(B2) + fv + N(p) + ws(oZ)](BxS(toa) + ON(K0) + qqN(D0) + kc(Kr));}();functio" ascii
    $s5  = "63\"+\"harAt\"](3);var xWU = \"ADO\";function a0(aK){var _112crap = \"s\"; return \"\" + aK + \"\";};function Cqk(B4){var _112cr" ascii
    $s6  = " \"\";};function HhN(Wtd){var _112crap = \"s\"; return \"\" + Wtd + \"\";};var Se = \"Hror6e8Mh\",r1 = Se[\"\"+\"\\x63\"+\"harAt" ascii
    $s7  = "urn \"\" + IGK + \"\";};function Pqw(g4){var _112crap = \"s\"; return \"\" + g4 + \"\";};var S = \"3onG\",cN = S[\"\"+\"\\x63\"+" ascii
    $s8  = " PMK = \"e\",I = tqB[\"\"+\"\\x63\"+\"harAt\"](5);function tUW(tUx){var _112crap = \"s\"; return \"\" + tUx + \"\";};function Hg" ascii
    $s9  = "xE = IR[\"\"+\"\\x63\"+\"harAt\"](2);function J7(O6){var _112crap = \"s\"; return \"\" + O6 + \"\";};function BY(IGK){var _112cr" ascii
    $s10 = "l == LKY) && (l == true)) ? true : false;};if (l && B() && LKY){function sxm() {return g[Ewg + Rky(uVa) + AZ(o1) + Ha + K3(VrX) " ascii
    $s11 = "o2(ps) + s3(L0)] < 4 ) {WScript[db + G1(E0)](UW() * 10)};HhJ = false;} catch(nd){HhJ = (h1(pQz) + e0, gNm + V(h2) + sg(g2), a0(g" ascii
    $s12 = "+\"harAt\"](1),W = eDS[\"\"+\"\\x63\"+\"harAt\"](5);var C = frD[\"\"+\"\\x63\"+\"harAt\"](1),Jx = \"M\\x53X\";var g0 = \"R\\x75" ascii
    $s13 = "73e\";var c = \"Resp\",M1 = \"pwj\";var n2 = \"r\\x69\\x74e\",M2 = M1[\"\"+\"\\x63\"+\"harAt\"](1);function ZtQ(jRh){var _112cra" ascii
    $s14 = "\\x65ep\",UD = \"S\";function r5(cJ){var _112crap = \"s\"; return \"\" + cJ + \"\";};function JQP(QA){var _112crap = \"s\"; retu" ascii
    $s15 = "Icx = \"2gH5PtCFMj\",L0 = \"\\x61te\";var ps = Icx[\"\"+\"\\x63\"+\"harAt\"](5),U0 = \"\\x79s\";var Fol = \"ad\",DRA = \"re\";fu" ascii
    $s16 = "\"CMil\",a = vq[\"\"+\"\\x63\"+\"harAt\"](3);var Ucq = Sec[\"\"+\"\\x63\"+\"harAt\"](5),Ja = \"\\x67et\";function B3(H0){var _11" ascii
    $s17 = "12crap = \"s\"; return \"\" + JV + \"\";};function QK(PQ){var _112crap = \"s\"; return \"\" + PQ + \"\";};var tqB = \"1o1rRsCg\"" ascii
    $s18 = "eturn \"\" + B4 + \"\";};function pj(eq){var _112crap = \"s\"; return \"\" + eq + \"\";};var Hh = \"a\",r6 = \"af\";var gd = \"" ascii
    $s19 = "4 = \"si\\x74\\x69\\x6f\",Ari = \"\\x70o\";function sN(NNn){var _112crap = \"s\"; return \"\" + NNn + \"\";};var xze = \"\\x42od" ascii
    $s20 = "n p1(p2){var _112crap = \"s\"; return \"\" + p2 + \"\";};function wrV(h0){var _112crap = \"s\"; return \"\" + h0 + \"\";};functi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}