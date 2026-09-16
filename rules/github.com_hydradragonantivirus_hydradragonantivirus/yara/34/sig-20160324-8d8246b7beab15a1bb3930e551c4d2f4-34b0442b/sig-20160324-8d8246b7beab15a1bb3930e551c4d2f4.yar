rule sig_20160324_8d8246b7beab15a1bb3930e551c4d2f4 {
  meta:
    description = "datamaliciousorder - file 20160324_8d8246b7beab15a1bb3930e551c4d2f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14593d3d831859262040d3503d2aff1ee96515a54e0622fc83483c86ecf99fc7"

  strings:
    $s1  = "var JcZ = \"\\x65\",dW = \"clo\\x73\";function qG(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};var Wj = \"oFil\\x65\",RbE" ascii
    $s2  = "unction DB(g){var _112crap = \"s\"; return \"\" + g + \"\";};var yr = \"\\x78\",z0 = \"n3sj\\x61\";var OSu = \".com\\x2f\",Wm = " ascii
    $s3  = "P = 0,pq = 0;function lz(){var Tx = new this[J](),e = Tx[hwT + nJ + AjO + D]();WScript[QR(WEK) + ab](E0());var Tx = new this[J](" ascii
    $s4  = "x61\",A = false;var hAY = \"CreateObject\",rP = function vS() {return WScript[hAY](r + Ck + z);}();var JbR = 123213,NB = \"MSXML" ascii
    $s5  = "F + JP + eug + QG](zb + Gpw) + czd + RDN + hlT + Qo(K);}; R0 = TSM(); vR = WScript[hAY](R0); var GPy = 1; while (GPy){try {vR[yu" ascii
    $s6  = "),Y = Tx[hwT + nJ + iI(AjO) + D]();WScript[WEK + MT(ab)](E0());var Tx = new this[J](),iVg = Tx[hwT + Ux(nJ) + AjO + D]();var P =" ascii
    $s7  = "(QJ)](cHk(X0), ct(im) + pW + Wm + OSu + z0 + DB(yr), false);vR[mP]();PR = \"Sleep\";while (vR[gNk + SM + MLX] < 4 ) {WScript[PR]" ascii
    $s8  = "reak;}}function E() {return ((de == true) && (de == vCv)) ? 1 : zqm;};if (de && E() && vCv){function csf() {return rP[o + k + mz" ascii
    $s9  = " \"Z\";P = R(Y, e);var pq = \"jb\";pq = R(iVg, Y);return R(P, pq);}var de = false,vCv = false;for (var OBm = zqm; OBm < E0() * 1" ascii
    $s10 = "var JcZ = \"\\x65\",dW = \"clo\\x73\";function qG(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};var Wj = \"oFil\\x65\",RbE" ascii
    $s11 = "p = \"s\"; return \"\" + UG + \"\";};var uR = \"o\\x64y\",j = \"ns\\x65B\";var bTQ = \"Resp\\x6f\",q1 = \"\\x65\";var R1 = \"wr" ascii
    $s12 = "Xk){var _112crap = \"s\"; return \"\" + Xk + \"\";};var QJ = \"o\\x70\\x65\\x6e\";function Qo(AKe){var _112crap = \"s\"; return " ascii
    $s13 = "ap = \"s\"; return \"\" + IE + \"\";};function MT(hbb){var _112crap = \"s\"; return \"\" + hbb + \"\";};var ab = \"\\x70\",WEK =" ascii
    $s14 = "m++){if (lz() != zqm){de = true; pq = \"07t9gasdf76ags\" + 123313 * P + pq; vCv = true; pq = \"07t9gasdf76ags\" + 123313 * P + p" ascii
    $s15 = "unction iI(L){var _112crap = \"s\"; return \"\" + L + \"\";};function Ux(n){var _112crap = \"s\"; return \"\" + n + \"\";};var D" ascii
    $s16 = "65\\x54\";function iv(a){var _112crap = \"s\"; return \"\" + a + \"\";};var g0 = \"t\\x69on\",m1 = \"p\\x6f\\x73i\";function WU(" ascii
    $s17 = "e\";var m0 = \"ope\\x6e\";function h(rs){var _112crap = \"s\"; return \"\" + rs + \"\";};var A0 = \"a\\x6d\",gOZ = \"\\x2eS\\x74" ascii
    $s18 = "73ta\";var gNk = \"re\\x61d\",ie = \"\\x70\";var m = \"S\\x6cee\",mP = \"sen\\x64\";function ct(N){var _112crap = \"s\"; return " ascii
    $s19 = "LHTTP\";var G = 2123213,zqm = 0;function S(iTY){rP[BYd](iTY, zqm, zqm);};function TSM(){return NB;};function R(EM, iM){return EM" ascii
    $s20 = "HV = \"\\x64s\",P0 = \"e\\x63on\";var Ag = \"\\x6c\\x6cis\",ro = \"T\\x43M\\x69\";var X = \"ge\\x74U\",eLn = \"D\\x61te\";functi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}