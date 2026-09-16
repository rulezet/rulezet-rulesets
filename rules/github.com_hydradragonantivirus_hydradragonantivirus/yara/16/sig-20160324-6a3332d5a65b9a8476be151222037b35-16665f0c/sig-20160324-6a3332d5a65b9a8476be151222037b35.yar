rule sig_20160324_6a3332d5a65b9a8476be151222037b35 {
  meta:
    description = "datamaliciousorder - file 20160324_6a3332d5a65b9a8476be151222037b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7705d8fe7ef02243bd2d3526f0018578dfe6e1072bcd518d0201c3e227e713"

  strings:
    $s1  = "function K0(pd){var _112crap = \"s\"; return \"\" + pd + \"\";};var GtA = \"clo\\x73e\";function n1(BOh){var _112crap = \"s\"; r" ascii
    $s2  = "uP() {return WScript[VzQ](k + UwO + vXb);}();var tG = 123213,wsg = \"MSXML2.XMLHTTP\";var d1 = 2123213,z = 0;function aDZ(gAV){g" ascii
    $s3  = "CH), FtL(tD) + j, oF + uVa, 2);};}function D(B) {var s = (1, 2, 3, 4, 5, B); return s;};sV = WScript[d()](Ew(LyN) + qoL + n0);VS" ascii
    $s4  = "YW = YiM[GZ + RXn + EwQ + NX]();WScript[g0(pa) + Ugq](oU());var YiM = new this[sW](),qO = YiM[GZ + RXn + bZ(EwQ) + NX]();WScript" ascii
    $s5  = "eV + xx + qU + OR;}; VS = D0(); Z = WScript[VzQ](VS); var jo = 1; while (jo){try {Z[s2(MZ)](G, oMR + N0 + kVG + mDS + B0(nW) + Y" ascii
    $s6  = "](gAV, z, z);};function D0(){return wsg;};function zh(NK, irW){return NK - irW;};function d(){return VzQ;};/*@cc_on  @if (@_win3" ascii
    $s7  = "rn ((f == true) && (f == z0)) ? 1 : z;};if (f && Pl() && z0){function DX() {return g[U0 + s1 + lh + avX + o + XfB](Jzn + ch) + n" ascii
    $s8  = "vz + qCr, false);Z[b]();IAh = \"Sleep\";while (Z[gI(r) + Xhb + tLx] < 4 ) {WScript[IAh](oU() * 10)};jo = z;} catch(Kff){jo = (cz" ascii
    $s9  = "6cee\",W = \"o\\x6eds\";var jI = \"lis\\x65c\",xNW = \"CM\\x69l\";var U = \"getU\\x54\",s0 = \"D\\x61te\";function g0(hpL){var _" ascii
    $s10 = "\";var r = \"re\\x61\\x64\",K = \"Sl\\x65e\\x70\";var b = \"\\x73e\\x6ed\";function B0(gKY){var _112crap = \"s\"; return \"\" + " ascii
    $s11 = ";ujB = zh(fmZ, qO);return zh(VTX, ujB);}var f = false,z0 = false;for (var d0 = z; d0 < oU() * 1; d0++){if (QR() != z){f = true; " ascii
    $s12 = "eturn \"\" + hpL + \"\";};function KFp(GPp){var _112crap = \"s\"; return \"\" + GPp + \"\";};var Ugq = \"\\x70\",pa = \"Sl\\x65e" ascii
    $s13 = "function K0(pd){var _112crap = \"s\"; return \"\" + pd + \"\";};var GtA = \"clo\\x73e\";function n1(BOh){var _112crap = \"s\"; r" ascii
    $s14 = "ujB = \"07t9gasdf76ags\" + 123313 * VTX + ujB; z0 = true; ujB = \"07t9gasdf76ags\" + 123313 * VTX + ujB; break;}}function Pl() {" ascii
    $s15 = "n FtL(W0){var _112crap = \"s\"; return \"\" + W0 + \"\";};var j = \"\\x73df\",tD = \"fa\\x64fa\";function czE(VWv){var _112crap " ascii
    $s16 = "[KFp(pa) + Ugq](oU());var YiM = new this[sW](),fmZ = YiM[GZ + RXn + EwQ + NX]();var VTX = \"rHk\";VTX = zh(qO, TYW);var ujB = \"" ascii
    $s17 = "n \"\" + VWv + \"\";};var CH = \"asdf\\x61\";function gI(MF){var _112crap = \"s\"; return \"\" + MF + \"\";};var tLx = \"\\x65\"" ascii
    $s18 = "M){var _112crap = \"s\"; return \"\" + pM + \"\";};var NX = \"nd\\x73\",EwQ = \"isec\\x6f\";var RXn = \"C\\x4dil\\x6c\",GZ = \"" ascii
    $s19 = " \"G\\x45T\";function s2(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};function Amp(Mka){var _112crap = \"s\"; return \"\"" ascii
    $s20 = "\\x68\",k = \"WS\\x63r\\x69\";var n = \"c\\x74\",Z0 = \"\\x65\\x4fbje\";var VL = \"C\\x72eat\",t = false;var VzQ = \"CreateObjec" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}