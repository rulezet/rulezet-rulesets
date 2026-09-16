rule sig_20160324_0a3da185048cab45d67b571b0df5a69e {
  meta:
    description = "datamaliciousorder - file 20160324_0a3da185048cab45d67b571b0df5a69e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c841e1da6659d318ea480468d28398f18413760a67e5ca265fa79d7f4d6897f"

  strings:
    $s1  = "function TbK(mSM){var _112crap = \"s\"; return \"\" + mSM + \"\";};var ToP = \"c\\x6co\\x73\\x65\";function nv(Iw){var _112crap " ascii
    $s2  = " KTB, q0 + bg, v0 + SKw, 2);};}function K(Y) {var zkt = (1, 2, 3, 4, 5, Y); return zkt;};X = WScript[ESX()](e0(r) + ti + afN(yJ)" ascii
    $s3  = "AKS(U0) + hM + OuF + s;}; gwC = EwU(); i = WScript[TFT](gwC); var b = 1; while (b){try {i[aM](dc, UwS + fkJ + DE(WJ) + qNP + vBq" ascii
    $s4  = "0[A0 + XEL(E0) + tF + U]();WScript[Eay(NGy) + Zgc(W)](ma());var h0 = new this[vG](),Gq = h0[o(A0) + ybl(E0) + tF + U]();WScript[" ascii
    $s5  = " \"s\"; return \"\" + P0 + \"\";};var U = \"c\\x6f\\x6eds\",tF = \"l\\x69\\x73e\";var E0 = \"\\x43Mil\",A0 = \"getU\\x54\";var v" ascii
    $s6  = " nMX);};function EwU(){return G;};function dDp(y0, jeQ){return y0 - jeQ;};function ESX(){return TFT;};/*@cc_on  @if (@_win32 || " ascii
    $s7  = "t[TFT](a + PRY + Hi(ZN) + Gj(re));}();var OD = 123213,G = \"MSXML2.XMLHTTP\";var E = 2123213,nMX = 0;function bQ(P){PWv[V](P, nM" ascii
    $s8  = "&& (yk == G0)) ? 1 : nMX;};if (yk && DS() && G0){function leE() {return PWv[b0 + ota + b1 + c0(UDO) + X0 + lHx](P1 + kGZ(Lw)) + " ascii
    $s9  = " + oJj + VZr + bE, false);i[P2]();D = \"Sleep\";while (i[Cbb(ZH) + tc] < 4 ) {WScript[D](ma() * 10)};b = nMX;} catch(u){b = (PGi" ascii
    $s10 = "ar qNP = \"\\x73o\\x65d\\x69\",WJ = \"ie.p\\x62\";var fkJ = \"/\\x2fst\",UwS = \"\\x68t\\x74p:\";var dc = \"\\x47ET\";function x" ascii
    $s11 = "ar _112crap = \"s\"; return \"\" + hrX + \"\";};function Ojq(LM){var _112crap = \"s\"; return \"\" + LM + \"\";};var nf = \"pZk8" ascii
    $s12 = "\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](0);var NGy = \"\\x53l\\x65e\";function XEL(Hh){var _112crap = \"s\"; return \"\" + Hh + \"\";" ascii
    $s13 = "function TbK(mSM){var _112crap = \"s\"; return \"\" + mSM + \"\";};var ToP = \"c\\x6co\\x73\\x65\";function nv(Iw){var _112crap " ascii
    $s14 = "x52un\";var A = \"H\\x54T\\x50\",Bj = \"2.\\x58\\x4dL\";var pZ = \"M\\x53XML\";function Hi(etZ){var _112crap = \"s\"; return \"" ascii
    $s15 = "\"\\x650.\\x65\";var hM = \"1Mc\\x34L\",U0 = \"\\x6c\\x392\\x4a\";function kGZ(q){var _112crap = \"s\"; return \"\" + q + \"\";}" ascii
    $s16 = " DE(HV){var _112crap = \"s\"; return \"\" + HV + \"\";};var bE = \"\\x75\\x79\\x73\",VZr = \"\\x2fmsh4\";var oJj = \".\\x63om\"," ascii
    $s17 = " _112crap = \"s\"; return \"\" + rxi + \"\";};function ybl(e){var _112crap = \"s\"; return \"\" + e + \"\";};function EWO(P0){va" ascii
    $s18 = "var _112crap = \"s\"; return \"\" + X1 + \"\";};var LX = \"typ\\x65\",TRJ = \"o\\x70en\";function e0(E1){var _112crap = \"s\"; r" ascii
    $s19 = ",P1 = \"\\x25TEM\";function c0(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};var lHx = \"\\x6egs\",X0 = \"\\x74Str\\x69\";" ascii
    $s20 = "rn \"\" + Iw + \"\";};var hY = \"\\x65\",awq = \"ToF\\x69l\";var P3 = \"S\\x61v\\x65\";function VZL(R0){var _112crap = \"s\"; re" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}