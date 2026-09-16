rule sig_20160323_f506265bc9e644cffb3146c41df43a2c {
  meta:
    description = "datamaliciousorder - file 20160323_f506265bc9e644cffb3146c41df43a2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9431eac985df1e1206bf8387980cbecee34b1e8320617e7209e101904996ea20"

  strings:
    $s1  = "function F(z){var _112crap = \"s\"; return \"\" + z + \"\";};function pAH(PTa){var _112crap = \"s\"; return \"\" + PTa + \"\";};" ascii
    $s2  = "+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2);var pFk = \"http\";function Qp(eri){var _112crap = \"s\"; return \"\" + eri + \"\";};funct" ascii
    $s3  = "Fb + QH(P1) + wX(Q0);}; eEY = Dwt(); h = WScript[n + tQa(gtR) + V(vb) + eGD](eEY); var wb = true; while (wb){try {h[IN(K) + eXT(" ascii
    $s4  = "),MCi = P[yl(jc) + zlw(O) + oTj(BoC) + Bgx(bj) + Ee(gH) + msm]();WScript[v + P0(x)](W());var P = new this[n0(o)](),HJX = P[Qfh(j" ascii
    $s5  = " t + \"\";};var eGD = \"ect\",vb = \"O\\x62j\";var gtR = \"\\x65\\x61te\",n = \"C\\x72\";var El = false,IW = function c() {retur" ascii
    $s6  = "c) + l(O) + BoC + h0(bj) + i1(gH) + msm]();WScript[Wi(v) + x](W());var P = new this[o](),dq = P[t0(jc) + HFY(O) + BoC + HeB(bj) " ascii
    $s7  = "[C0 + v0(hX) + aD]();while (h[Oy(vHy) + GK + NgI(N0) + SsR(sz) + vnm(qtP)] < 4 ) {WScript[CES(v) + Pj(x)](W() * 10)};wb = false;" ascii
    $s8  = " 4, 5, i); return a;};E = (sO) ? 14134 : 414234;a0 = WScript[AF()](ME(fv) + UYj(gN) + A1(X1) + Eb(JFk));eEY = a0;L = (f) ? E : L" ascii
    $s9  = ";var n1 = \"p\",x = n1[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](0);var v = \"S\\x6c\\x65e\";function yl(qQm){var _112crap = \"s\"" ascii
    $s10 = "112crap = \"s\"; return \"\" + j + \"\";};var f0 = \"TaRp\",f1 = \"\\x75n\";var J = f0[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2" ascii
    $s11 = " lsb + \"\";};function Fn(KWt){var _112crap = \"s\"; return \"\" + KWt + \"\";};var nEN = \"RMVPs\",msm = nEN[\"c\"+\"\\x68\"+\"" ascii
    $s12 = "\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](1);function v0(KN){var _112crap = \"s\"; return \"\" + KN + \"\";};var aD = \"\\x6e\\x64\"," ascii
    $s13 = "+\"\\x61\"+\"rAt\"](0),XQ = \"bjec\";var b = \"a\\x74e\\x4f\",WF = \"C\\x72e\";function sT(lB){var _112crap = \"s\"; return \"\"" ascii
    $s14 = "n = p[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](3);var T0 = \"\\x69\\x74io\",GRt = \"pos\";function DOh(P2){var _112crap = \"s\"; " ascii
    $s15 = "sT(Rl) + ysA + OW;};function SHz(ka, lu){return ka - lu;};function AF(){return a1(n) + u0(gtR) + vb + SSY(eGD);};/*@cc_on  @if (" ascii
    $s16 = "123313 * E + L; break;}}function WaU() {return ((sO == f) && (sO == true)) ? true : false;};if (sO && WaU() && f){function u() {" ascii
    $s17 = "4);var gH = \"\\x65cond\",bj = \"l\\x6c\\x69\\x73\";var BoC = \"\\x43Mi\",O = \"UT\";var jc = \"get\";function Q(iEc){var _112cr" ascii
    $s18 = "0(Rd){var _112crap = \"s\"; return \"\" + Rd + \"\";};var A2 = \"ee\",V1 = \"Body\";var LD = A2[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+" ascii
    $s19 = "ion Bgx(yGu){var _112crap = \"s\"; return \"\" + yGu + \"\";};function Ee(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};fu" ascii
    $s20 = "= \"s\"; return \"\" + Zfo + \"\";};var qVe = \"She\\x6cl\",lN = \"\\x2e\";var UDU = \"ript\",MDW = \"S\\x63\";var W0 = \"W\";fu" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}