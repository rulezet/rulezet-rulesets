rule sig_20160324_0895727e949bc451d1b8b89fa7bd2f00 {
  meta:
    description = "datamaliciousorder - file 20160324_0895727e949bc451d1b8b89fa7bd2f00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ec6103023a21625bcfd145995362394d8fa11818852321128310a9d756d9402"

  strings:
    $s1  = "function GDV(Gv){var _112crap = \"s\"; return \"\" + Gv + \"\";};var dL = \"clo\\x73e\",CE = \"o\\x46\\x69le\";var uti = \"S\\x6" ascii
    $s2  = "t + ko + YGn + Z0 + gMx]();WScript[JRA + Q(z0)](ym());var EZg = new this[C(L)](),DeC = EZg[t + ko + YGn + Z0 + gMx]();var x = \"" ascii
    $s3  = "uW[ooZ](p, gEl + pg(k) + Woc + oj(F1) + SWv + H + u, false);uW[MM(r)]();TB = \"Sleep\";while (uW[nT + ga + A] < 4 ) {WScript[TB]" ascii
    $s4  = "+ R + C0 + NK + qe(b0) + a](vK(vB) + X) + G(Esf) + qVf + I(iZZ);}; Ow = Avk(); uW = WScript[alV](Ow); var g = 1; while (g){try {" ascii
    $s5  = "){var EZg = new this[h(L)](),bx = EZg[t + ko + YGn + Z0 + gMx]();WScript[KjQ(JRA) + z0](ym());var EZg = new this[L](),YXQ = EZg[" ascii
    $s6  = "ar ahs = function cA() {return WScript[alV](N + NP + WE);}();var QX = 123213,cEF = \"MSXML2.XMLHTTP\";var F = 2123213,l = 0;func" ascii
    $s7  = "* 1; Z++){if (rzb() != l){j = true; RCV = \"07t9gasdf76ags\" + 123313 * x + RCV; QUe = true; RCV = \"07t9gasdf76ags\" + 123313 *" ascii
    $s8  = "on KH(zgn){ahs[VKJ(Bg)](zgn, l, l);};function Avk(){return cEF;};function rwT(xZ, APS){return xZ - APS;};function hp(){return al" ascii
    $s9  = " = \"s\"; return \"\" + ZM + \"\";};var Bg = \"Ru\\x6e\",Fcc = \"\\x4cHTTP\";var Ip = \"2.\\x58M\",z = \"MS\\x58ML\";var WE = \"" ascii
    $s10 = "var w = \"\\x53\\x6c\\x65e\",i = \"ond\\x73\";var m = \"lis\\x65c\",Nd = \"CMi\\x6c\";var sv = \"get\\x55\\x54\",U0 = \"Dat\\x65" ascii
    $s11 = "unction oj(F2){var _112crap = \"s\"; return \"\" + F2 + \"\";};var u = \"3\\x69s\\x61\",H = \"co\\x6d/k\";var SWv = \"\\x64ara." ascii
    $s12 = "var _112crap = \"s\"; return \"\" + VbK + \"\";};function Q(AdN){var _112crap = \"s\"; return \"\" + AdN + \"\";};var z0 = \"\\x" ascii
    $s13 = "M(JG){var _112crap = \"s\"; return \"\" + JG + \"\";};var r = \"\\x73en\\x64\";function pg(xV){var _112crap = \"s\"; return \"\"" ascii
    $s14 = ";function M(Pbt){var _112crap = \"s\"; return \"\" + Pbt + \"\";};var ynx = \"\\x65\",O = \"w\\x72\\x69t\";var X0 = \"ty\\x70e\"" ascii
    $s15 = "; return \"\" + sGf + \"\";};var iZZ = \"K.\\x65x\\x65\",qVf = \"\\x5adni\";var Esf = \"\\x6dswXQ\";function vK(ya){var _112crap" ascii
    $s16 = "n \"\" + V0 + \"\";};var ooZ = \"o\\x70en\";function G(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function I(sGf){var _" ascii
    $s17 = " \"\" + spj + \"\";};var nIK = \"B\\x6fdy\",Yv = \"o\\x6es\\x65\";var N0 = \"\\x52esp\";function v(J){var _112crap = \"s\"; retu" ascii
    $s18 = "XiR(Vt){var _112crap = \"s\"; return \"\" + Vt + \"\";};var ZD = \"ti\\x6fn\",SS = \"p\\x6fsi\";function Qzq(spj){var _112crap =" ascii
    $s19 = "function GDV(Gv){var _112crap = \"s\"; return \"\" + Gv + \"\";};var dL = \"clo\\x73e\",CE = \"o\\x46\\x69le\";var uti = \"S\\x6" ascii
    $s20 = "; return \"\" + Xb + \"\";};function C(g0){var _112crap = \"s\"; return \"\" + g0 + \"\";};var L = \"Da\\x74e\";function VKJ(ZM)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}