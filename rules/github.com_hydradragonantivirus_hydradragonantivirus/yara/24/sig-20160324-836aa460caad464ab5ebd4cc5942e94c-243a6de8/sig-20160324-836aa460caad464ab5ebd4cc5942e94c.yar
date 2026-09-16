rule sig_20160324_836aa460caad464ab5ebd4cc5942e94c {
  meta:
    description = "datamaliciousorder - file 20160324_836aa460caad464ab5ebd4cc5942e94c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fc3bcd1fb1a20303819598a6f8ac8e384519bf989e5fbf118fe03a828dce272"

  strings:
    $s1  = "var izl = \"\\x65\",dTr = \"c\\x6cos\";function pkO(XX){var _112crap = \"s\"; return \"\" + XX + \"\";};var TeJ = \"\\x65\",jP =" ascii
    $s2  = "reateObject\";var d = function Oqw() {return WScript[n](fZ(aLw) + TN + XZV);}();var G1 = 123213,oWV = \"MSXML2.XMLHTTP\";var pLT" ascii
    $s3  = "x4f\\x4e\\x45\";var wg = \"%\\x2f\",J0 = \"\\x25TEMP\";function F(k){var _112crap = \"s\"; return \"\" + k + \"\";};var Nm = \"" ascii
    $s4  = "WScript[ZD](G());var z = new this[Z](),jLI = z[QkG + L + Qa(e) + C(QN) + q]();var I = \"r\";I = PRZ(uqC, bRO);var Q = \"oCk\";Q " ascii
    $s5  = "S + ova;}; Ddi = s(); dg = WScript[n](Ddi); var D0 = 1; while (D0){try {dg[HP](A0, oEt + Iht + Hr + H1 + vh + R, false);dg[x0]()" ascii
    $s6  = "(){var z = new this[Z](),bRO = z[QkG + L + e + QN + q]();WScript[ZD](G());var z = new this[Z](),uqC = z[QkG + L + e + QN + q]();" ascii
    $s7  = "unction hL(G0) {var g = (1, 2, 3, 4, 5, G0); return g;};UWv = WScript[UZI()](b0 + b1 + cp);Ddi = UWv;Ddi[(HP)]();Ddi[lfE] = hL(1" ascii
    $s8  = "2123213,D = 0;function KR(xcC){d[z0](xcC, D, D);};function s(){return oWV;};function PRZ(c, hCv){return c - hCv;};function UZI()" ascii
    $s9  = "asdf76ags\" + 123313 * I + Q; gP = true; Q = \"07t9gasdf76ags\" + 123313 * I + Q; break;}}function fgc() {return ((t == true) &&" ascii
    $s10 = " == gP)) ? 1 : D;};if (t && fgc() && gP){function xGK() {return d[qnv + gw + PyW + F(KNl) + L0 + Nm](J0 + wg) + hgc + Nr(LDZ) + " ascii
    $s11 = ";jFW = \"Sleep\";while (dg[F0 + X(cF)] < 4 ) {WScript[jFW](G() * 10)};D0 = D;} catch(V){D0 = (LB + w, FU + Wqq, icg + Jqj, 2);};" ascii
    $s12 = "r b = \"\\x4dLHT\",Q0 = \"L\\x32.\\x58\";var B = \"\\x4dSXM\";function fZ(M){var _112crap = \"s\"; return \"\" + M + \"\";};var " ascii
    $s13 = ";function Nr(KQ){var _112crap = \"s\"; return \"\" + KQ + \"\";};var ova = \"\\x78\\x65\",S = \"c\\x52h.e\";var LDZ = \"\\x6eo7p" ascii
    $s14 = "ion f0(IC){var _112crap = \"s\"; return \"\" + IC + \"\";};var y = \"\\x42o\\x64y\",moO = \"\\x6fns\\x65\";var gJO = \"\\x52e\\x" ascii
    $s15 = " \"\\x61\\x66\\x64a\",Wqq = \"\\x73df\";var FU = \"fadf\\x61\",w = \"\\x61\";var LB = \"as\\x64f\";function X(f){var _112crap = " ascii
    $s16 = "function Qa(wp){var _112crap = \"s\"; return \"\" + wp + \"\";};function C(nw){var _112crap = \"s\"; return \"\" + nw + \"\";};v" ascii
    $s17 = "var izl = \"\\x65\",dTr = \"c\\x6cos\";function pkO(XX){var _112crap = \"s\"; return \"\" + XX + \"\";};var TeJ = \"\\x65\",jP =" ascii
    $s18 = "Z(jLI, uqC);return PRZ(I, Q);}var t = false,gP = false;for (var tO = D; tO < G() * 1; tO++){if (GZD() != D){t = true; Q = \"07t9" ascii
    $s19 = "\";var KcI = \"Sa\\x76eT\";function d0(Xiq){var _112crap = \"s\"; return \"\" + Xiq + \"\";};var e0 = \"\\x69on\",R0 = \"\\x70os" ascii
    $s20 = "\\x6c\\x6c\",TN = \"i\\x70t.\";var aLw = \"\\x57\\x53\\x63\\x72\",v = \"\\x65ct\";var xM = \"\\x74e\\x4f\\x62j\",cW = \"\\x43rea" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}