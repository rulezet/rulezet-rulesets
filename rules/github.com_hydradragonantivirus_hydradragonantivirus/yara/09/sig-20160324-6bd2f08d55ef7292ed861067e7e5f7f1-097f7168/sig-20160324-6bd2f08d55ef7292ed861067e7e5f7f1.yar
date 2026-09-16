rule sig_20160324_6bd2f08d55ef7292ed861067e7e5f7f1 {
  meta:
    description = "datamaliciousorder - file 20160324_6bd2f08d55ef7292ed861067e7e5f7f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "687d32bd859fc80cb08ff28afb3af5f7a358b0615c7646fdc6fd6d4140efd329"

  strings:
    $s1  = "var a0 = \"\\x63lose\",xV = \"\\x6f\\x46ile\";var kA = \"S\\x61veT\";function BtI(h){var _112crap = \"s\"; return \"\" + h + \"" ascii
    $s2  = "\\x62j\",xFY = \"\\x43reat\";var JKd = false,C = \"CreateObject\";var A0 = function Huw() {return WScript[C](V0 + d + Nej);}();v" ascii
    $s3  = "ar Rf = new this[p](),Nq = Rf[o + JZG + oh + jMQ]();WScript[Qi + sFh](im());var Rf = new this[p](),eJc = Rf[o + JZG + oh + ei(jM" ascii
    $s4  = " myI = (1, 2, 3, 4, 5, c); return myI;};JNa = WScript[K()](H + rVF + aKr(ZCq));lo = JNa;lo[(Q0(b))]();lo[MI] = uKH(1);lo[Wj](Mik" ascii
    $s5  = "n im(){return 22;};var RNi = 0,X = 0;function f(){var Rf = new this[p](),qM = Rf[o + JZG + oh + jMQ]();WScript[Qi + sFh](im());v" ascii
    $s6  = "313 * RNi + X; break;}}function RN() {return ((A == true) && (A == BU)) ? 1 : Rg;};if (A && RN() && BU){function r() {return A0[" ascii
    $s7  = "r1) + GLY] < 4 ) {WScript[nxC](im() * 10)};il = Rg;} catch(sB){il = (fp, hp(Fc) + oo, pTd + sHT(mAx), 2);};}function uKH(c) {var" ascii
    $s8  = "\\x74\\x70\";var qDj = \"G\\x45T\";function uL(of){var _112crap = \"s\"; return \"\" + of + \"\";};function Q0(ZK){var _112crap " ascii
    $s9  = "e (il){try {Mik[uL(b)](qDj, em(GKz) + rl + NQ + vz(bE) + hI + RP + TP + wPL, false);Mik[Rm]();nxC = \"Sleep\";while (Mik[mww + b" ascii
    $s10 = "unction em(NdD){var _112crap = \"s\"; return \"\" + NdD + \"\";};function vz(REi){var _112crap = \"s\"; return \"\" + REi + \"\"" ascii
    $s11 = "var a0 = \"\\x63lose\",xV = \"\\x6f\\x46ile\";var kA = \"S\\x61veT\";function BtI(h){var _112crap = \"s\"; return \"\" + h + \"" ascii
    $s12 = "%\\x2f\";var IVX = \"%\\x54EM\";function HQR(rdV){var _112crap = \"s\"; return \"\" + rdV + \"\";};function p0(GyS){var _112crap" ascii
    $s13 = "urn \"\" + GyS + \"\";};function d0(mj){var _112crap = \"s\"; return \"\" + mj + \"\";};var Be = \"\\x73\",S = \"\\x72i\\x6e\\x6" ascii
    $s14 = "\"\" + bKR + \"\";};var oo = \"s\\x64\\x66\",Fc = \"f\\x61dfa\";var fp = \"asd\\x66\\x61\";function b0(b1){var _112crap = \"s\";" ascii
    $s15 = "x65n\";function aKr(Tr){var _112crap = \"s\"; return \"\" + Tr + \"\";};var ZCq = \"ea\\x6d\",rVF = \".St\\x72\";var H = \"ADO" ascii
    $s16 = "sHT(Wl){var _112crap = \"s\"; return \"\" + Wl + \"\";};var mAx = \"f\\x61\",pTd = \"af\\x64a\";function hp(bKR){var _112crap = " ascii
    $s17 = ";var Xd = \"\\x67etUT\",UJK = \"\\x44\\x61te\";var sFh = \"\\x70\",Qi = \"\\x53lee\";function ei(TmW){var _112crap = \"s\"; retu" ascii
    $s18 = "Rg; IE < im() * 1; IE++){if (f() != Rg){A = true; X = \"07t9gasdf76ags\" + 123313 * RNi + X; BU = true; X = \"07t9gasdf76ags\" +" ascii
    $s19 = "= 123213,uHr = \"MSXML2.XMLHTTP\";var TJR = 2123213,Rg = 0;function g(QD){A0[D](QD, Rg, Rg);};function pDk(){return uHr;};functi" ascii
    $s20 = " qLS(k, YfO){return k - YfO;};function K(){return C;};/*@cc_on  @if (@_win32 || @_win64)    JKd = true;  @end@*/if (JKd){functio" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}