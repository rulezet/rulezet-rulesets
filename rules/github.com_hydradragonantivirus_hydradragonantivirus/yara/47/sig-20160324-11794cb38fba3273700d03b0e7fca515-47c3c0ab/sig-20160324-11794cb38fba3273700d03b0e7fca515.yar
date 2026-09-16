rule sig_20160324_11794cb38fba3273700d03b0e7fca515 {
  meta:
    description = "datamaliciousorder - file 20160324_11794cb38fba3273700d03b0e7fca515.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47efecd385c7b9f5912ef86e70d16ddddf49327af7024cdda5d11baf910f8dfa"

  strings:
    $s1  = "function IJ(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};var tBS = \"\\x65\",K2 = \"clo\\x73\";var jG = \"\\x6ce\",JBn = " ascii
    $s2  = "r WpX = function xK() {return WScript[q](vZ + fP(x) + uP);}();var IkU = 123213,MC = \"MSXML2.XMLHTTP\";var eYu = 2123213,h = 0;f" ascii
    $s3  = " = new this[tL](),ilP = J[c(s) + BbL + es + BO + S]();WScript[aZ(rk)](m());var J = new this[tL](),OvZ = J[s + BbL + Vz(es) + C0(" ascii
    $s4  = " = (B(h0) + j, W(Jn) + cg, UG(r) + MU, 2);};}function X(Cs) {var gE = (1, 2, 3, 4, 5, Cs); return gE;};nKo = WScript[nf()](mFC +" ascii
    $s5  = "BO) + S]();WScript[V0(rk)](m());var J = new this[tL](),WlA = J[pEu(s) + BbL + es + F(BO) + S]();var ZP = \"O\";ZP = hgs(OvZ, ilP" ascii
    $s6  = "(de + YkV) + oar + Of + zx + qns;}; uB = dV(); e0 = WScript[q](uB); var pP = 1; while (pP){try {e0[M(wlR)](ej(Um), aH + HIe + A " ascii
    $s7  = "ction C(YyM){WpX[Z](YyM, h, h);};function dV(){return MC;};function hgs(uAL, Ukj){return uAL - Ukj;};function nf(){return q;};/*" ascii
    $s8  = "() {return ((R == true) && (R == VFq)) ? 1 : h;};if (R && Q() && VFq){function e() {return WpX[ill + sXl + sHB(G) + l + Jw + s0]" ascii
    $s9  = "+ jq + x1 + rJ + iM, false);e0[Vb(Ah)]();H = \"Sleep\";while (e0[K1 + kUx + G0] < 4 ) {WScript[H](m() * 10)};pP = h;} catch(pL){" ascii
    $s10 = "112crap = \"s\"; return \"\" + kKm + \"\";};var Ah = \"s\\x65nd\",iM = \"\\x69\";var rJ = \"yt\\x37we\",x1 = \"\\x2e\\x6frg/\";v" ascii
    $s11 = "G = \"Sav\\x65\";function w0(qM){var _112crap = \"s\"; return \"\" + qM + \"\";};var UR = \"i\\x6fn\",eP = \"p\\x6fsit\";var Yt " ascii
    $s12 = "ar mK = \"\\x6c\\x6cise\",xd = \"TC\\x4di\";var nh = \"g\\x65\\x74U\",eF = \"\\x44a\\x74e\";function aZ(aZ0){var _112crap = \"s" ascii
    $s13 = " = \"\\x73kp\\x68\";var HIe = \"\\x3a/\\x2fm\",aH = \"\\x68ttp\";function ej(rM){var _112crap = \"s\"; return \"\" + rM + \"\";}" ascii
    $s14 = "\";var mFC = \"AD\\x4fD\";function UG(P){var _112crap = \"s\"; return \"\" + P + \"\";};var MU = \"f\\x61\",r = \"afd\\x61\";fun" ascii
    $s15 = "0 + \"\";};function V0(X1){var _112crap = \"s\"; return \"\" + X1 + \"\";};var rk = \"Sl\\x65ep\";function c(Z0){var _112crap = " ascii
    $s16 = "4c\\x48TT\\x50\";var V = \"\\x32\\x2eXM\",w = \"MS\\x58ML\";function fP(K){var _112crap = \"s\"; return \"\" + K + \"\";};var uP" ascii
    $s17 = "var cz = \"X0\";cz = hgs(WlA, OvZ);return hgs(ZP, cz);}var R = false,VFq = false;for (var Ni = h; Ni < m() * 1; Ni++){if (DCd() " ascii
    $s18 = " \"\";};function pEu(Ttg){var _112crap = \"s\"; return \"\" + Ttg + \"\";};function F(AN){var _112crap = \"s\"; return \"\" + AN" ascii
    $s19 = "_112crap = \"s\"; return \"\" + G1 + \"\";};var cg = \"\\x73df\",Jn = \"\\x66\\x61d\\x66a\";function B(Y){var _112crap = \"s\"; " ascii
    $s20 = "m\\x54\";var oar = \"\\x6fmRW\",YkV = \"\\x25\\x2f\";var de = \"%TE\\x4dP\";function sHB(UDy){var _112crap = \"s\"; return \"\" " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}