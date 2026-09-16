rule sig_20160323_51e97eb528a1c7492a2f85ac9f48d295 {
  meta:
    description = "datamaliciousorder - file 20160323_51e97eb528a1c7492a2f85ac9f48d295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc3e8dcefff4d28bdd8506716b261514beb3df0dc69bf275406d9dffd39047af"

  strings:
    $s1  = "function rtY(TP0){var _112crap = \"s\"; return \"\" + TP0 + \"\";};var L1 = \"ose\",We = \"c\\x6c\";function fM(ndj){var _112cra" ascii
    $s2  = "Tdq(zo) + SC]();WScript[YK(Lm)](rqN());var pF = new this[i + HF(nlt)](),RKq = pF[VVh + L(xRT) + tg(YA) + zo + SC]();var z = \"uW" ascii
    $s3  = "return uZz;};z = (v) ? 14134 : 414234;SoZ = WScript[y()](sP + tEP(I) + T3(Sh) + qT(Vob));OLr = SoZ;iG = (T) ? z : iG;OLr[(fD(Mh)" ascii
    $s4  = "J(xRT) + YA + dW(zo) + cP(SC)]();WScript[tE(Lm)](rqN());var pF = new this[yOK(i) + WwV(nlt)](),S = pF[KCS(VVh) + S0(xRT) + YA + " ascii
    $s5  = "false;var TP = function t() {return WScript[pR(NE) + mB(X) + cF + M0(v0) + rh(KPZ) + ZM + jtT](F0 + p0 + M1(MF) + Ith(SR) + Ls);" ascii
    $s6  = " + Q(A1) + rE;}; OLr = l(); fW = WScript[NE + s(X) + Vq(cF) + D(v0) + Dsv(KPZ) + ZM + WLE(jtT)](OLr); var DDE = true; while (DDE" ascii
    $s7  = "ar _112crap = \"s\"; return \"\" + ZDT + \"\";};var o = \"rUVs7R\",s0 = \"n\\x64\";var V = \"e\",J = o[\"c\"+\"\\x68\"+\"\"+\"" ascii
    $s8  = "P[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](2);function FXd(Xh){var _112crap = \"s\"; return \"\" + Xh + \"\";};function i0(c){var" ascii
    $s9  = "\"; return \"\" + ODp + \"\";};var D0 = \"o2d/j5Bx9\",L0 = D0[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](3);var K = \"\\x45M\\x50" ascii
    $s10 = "}();function na(M){TP[hxW](M, 0, 0);};function l(){return Ok(CiC) + a + lAt(IHj) + jO(tG) + f;};function xwe(e, FYp){return e - " ascii
    $s11 = " \"\";};function j(RDm){var _112crap = \"s\"; return \"\" + RDm + \"\";};var Y2 = \"\\x65\",zy = \"\\x79s\\x74\\x61t\";var rx = " ascii
    $s12 = ";}}function ArQ() {return ((v == T) && (v == true)) ? true : false;};if (v && ArQ() && T){function SD() {return TP[WQ(aHj) + yc(" ascii
    $s13 = "O2(w0), false);fW[H1(J) + xzd(V) + df(s0)]();while (fW[H2(rx) + k2(zy) + j(Y2)] < 4 ) {WScript[Lm](rqN() * 10)};DDE = false;} ca" ascii
    $s14 = "Eu = \"so\",r0 = \"ion\";var ghV = \"sit\",I0 = Eu[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](1);var N1 = \"p\";function E(JoT){var" ascii
    $s15 = "\\x69\",F0 = \"\\x57\\x53\";function pR(azI){var _112crap = \"s\"; return \"\" + azI + \"\";};function mB(SE){var _112crap = \"s" ascii
    $s16 = "\\x63\",VpG = \"\\x6bb\";var Y1 = \"6j7Y\";function XH(TB){var _112crap = \"s\"; return \"\" + TB + \"\";};function X0(ODp){var " ascii
    $s17 = "GQU = \"Res\";var gP = \"wpJeW\",YTt = \"\\x72ite\";var ge = gP[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](0);function G1(R1){var _" ascii
    $s18 = "e\",nlt = Df[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"rAt\"](0);var i = \"Dat\",d = \"\\x62ject\";var k = \"ateO\",w = \"Cre\";function " ascii
    $s19 = "rn \"\" + R1 + \"\";};var ewh = \"ty\\x70\\x65\",Yx = \"en\";var Ws = \"o\\x70\";function tEP(D2){var _112crap = \"s\"; return " ascii
    $s20 = "2crap = \"s\"; return \"\" + m1 + \"\";};function XIa(GTg){var _112crap = \"s\"; return \"\" + GTg + \"\";};var aCx = \"cdMNDtg1" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}