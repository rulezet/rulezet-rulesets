rule sig_20160324_0d5c80545b495b9184e2c6db00c9faff {
  meta:
    description = "datamaliciousorder - file 20160324_0d5c80545b495b9184e2c6db00c9faff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4d0f0538f10d9f91595c57d2a965a4fa84a9056832cccffefba0d2002de3c73"

  strings:
    $s1  = "function Gy(zU){var _112crap = \"s\"; return \"\" + zU + \"\";};var C1 = \"\\x65\",DQ = \"c\\x6cos\";var j = \"\\x6ce\",qNU = \"" ascii
    $s2  = "var i = function Yd() {return WScript[G](yWO + miq + rji(wPp));}();var OM = 123213,Pt = \"MSXML2.XMLHTTP\";var v = 2123213,H = 0" ascii
    $s3  = "G), exy + niN, Cm + Jfp, 2);};}function uQI(xi) {var pfo = (1, 2, 3, 4, 5, xi); return pfo;};vM = WScript[fC()](Fi(c0) + Zu + OK" ascii
    $s4  = "this[As(LZY)](),OTG = C0[Tk(gLo) + k + Wh(Q) + uc]();WScript[wPy](sz());var C0 = new this[LZY](),D = C0[gLo + k + Q + uc]();WScr" ascii
    $s5  = "+ tKs;}; USZ = X(); nQF = WScript[G](USZ); var F = 1; while (F){try {nQF[L1](wrF, Hny(o) + abb + u0(zLU) + vX + VR(BVH) + s + lN" ascii
    $s6  = "unction sJ(LI){i[aA](LI, H, H);};function X(){return Pt;};function qZ(ump, Ws){return ump - Ws;};function fC(){return G;};/*@cc_" ascii
    $s7  = " + 123313 * b + uM; a = true; uM = \"07t9gasdf76ags\" + 123313 * b + uM; break;}}function on() {return ((L == true) && (L == a))" ascii
    $s8  = " 1 : H;};if (L && on() && a){function yg() {return i[T + dYl(nH) + nf + qhy(h) + Ui(N) + kwn(V)](Prf(UMg) + hI) + OXS + dve(lN) " ascii
    $s9  = "U(o0), false);nQF[CAM]();UsY = \"Sleep\";while (nQF[R0 + w + Sf] < 4 ) {WScript[UsY](sz() * 10)};F = H;} catch(Jzq){F = (n + EJA" ascii
    $s10 = "\\x67\\x65tUT\";function As(v0){var _112crap = \"s\"; return \"\" + v0 + \"\";};var LZY = \"D\\x61\\x74e\",aA = \"Ru\\x6e\";var " ascii
    $s11 = "function Gy(zU){var _112crap = \"s\"; return \"\" + zU + \"\";};var C1 = \"\\x65\",DQ = \"c\\x6cos\";var j = \"\\x6ce\",qNU = \"" ascii
    $s12 = "2crap = \"s\"; return \"\" + rt + \"\";};function OKS(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};var cO = \"\\x65am\",Z" ascii
    $s13 = "\" + pKm + \"\";};function VR(Xq){var _112crap = \"s\"; return \"\" + Xq + \"\";};function lNU(R){var _112crap = \"s\"; return " ascii
    $s14 = " D);return qZ(b, uM);}var L = false,a = false;for (var C = H; C < sz() * 1; C++){if (YIC() != H){L = true; uM = \"07t9gasdf76ags" ascii
    $s15 = "ipt[wPy](sz());var C0 = new this[LZY](),TU = C0[CI(gLo) + L0(k) + Q + uc]();var b = \"ze\";b = qZ(D, OTG);var uM = \"z\";uM = qZ" ascii
    $s16 = " dYl(SIW){var _112crap = \"s\"; return \"\" + SIW + \"\";};function qhy(oo){var _112crap = \"s\"; return \"\" + oo + \"\";};func" ascii
    $s17 = "x37\";var OXS = \"Ri\\x39X\";function Prf(iLW){var _112crap = \"s\"; return \"\" + iLW + \"\";};var hI = \"%\\x2f\",UMg = \"%T" ascii
    $s18 = ":\",wrF = \"GE\\x54\";var L1 = \"ope\\x6e\";function dve(d){var _112crap = \"s\"; return \"\" + d + \"\";};var tKs = \"1.e\\x78e" ascii
    $s19 = "eturn \"\" + Pb + \"\";};function Wh(TGV){var _112crap = \"s\"; return \"\" + TGV + \"\";};function CI(Bv){var _112crap = \"s\";" ascii
    $s20 = "{var _112crap = \"s\"; return \"\" + FPI + \"\";};function kwn(Yd0){var _112crap = \"s\"; return \"\" + Yd0 + \"\";};var V = \"n" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}