rule sig_20160324_346c67e18df2b87aa8c9f9ecdd36eec7 {
  meta:
    description = "datamaliciousorder - file 20160324_346c67e18df2b87aa8c9f9ecdd36eec7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3afc6eada59548a964ae2165b413eb832fec0c116786b90b954efeb15d04f93d"

  strings:
    $s1  = "Y){h[zvw](dY, 0, 0);};function nI(){return h0 + qO + N0(Es) + Za;};function O(FTP, jKV){return FTP - jKV;};function AwD(){return" ascii
    $s2  = "H)](R());var kO = new this[qo(FDV) + kqo](),Rr = kO[w(Zm) + ey(WS) + cBE(gqz) + fR(l) + Dud(Pn)]();WScript[M0 + Y(OH)](R());var " ascii
    $s3  = "k) + KUh(ofd), true);};}function zIq(pBa) {var r = (1, 2, 3, 4, 5, pBa); return r;};u = (I) ? 14134 : 414234;FbJ = WScript[AwD()" ascii
    $s4  = "Script[HWW(aj) + O0(xB) + YTN + bC(p)](VIU); var tDf = true; while (tDf){try {blb[doG(kw) + Ygx(KEa)](S1(ZR), Gz(dR) + s(DI) + u" ascii
    $s5  = "function jNn(Bn){var _112crap = \"s\"; return \"\" + Bn + \"\";};function SzU(NL){var _112crap = \"s\"; return \"\" + NL + \"\";" ascii
    $s6  = "se,h = function uo() {return WScript[M(aj) + cdK(xB) + YTN + t(p)](wLx + uC(Kde) + O1(OTw) + Dj(nCn) + ZZ(xg));}();function CJ(d" ascii
    $s7  = "h = 0;function V(){var kO = new this[FDV + cC(kqo)](),Bq = kO[Zm + Qf(WS) + rSS(gqz) + wuF(l) + err(Pn)]();WScript[UqP(M0) + q(O" ascii
    $s8  = ") + c0(TO) + ZQS] < 4 ) {WScript[M0 + fMn(OH)](R() * 10)};tDf = false;} catch(X){tDf = (CIB(F2) + DG, RT(k0) + ri + h1(k1), hH(b" ascii
    $s9  = "= \"eat\\x65O\",Zh = \"Cr\";function Jk(l1){var _112crap = \"s\"; return \"\" + l1 + \"\";};function dB(g){var _112crap = \"s\";" ascii
    $s10 = "return \"\" + HX0 + \"\";};function CU(R1){var _112crap = \"s\"; return \"\" + R1 + \"\";};function s0(vF){var _112crap = \"s\";" ascii
    $s11 = "n N0(rwC){var _112crap = \"s\"; return \"\" + rwC + \"\";};var yAj = \"8FMVHF\",Za = \"LHT\\x54\\x50\";var Es = yAj[\"char\"+\"" ascii
    $s12 = " = \"open\";function t0(m){var _112crap = \"s\"; return \"\" + m + \"\";};var r1 = \"r\\x65am\",d0 = \"\\x42\\x2eS\\x74\";var sf" ascii
    $s13 = "return \"\" + oS + \"\";};function w(cdG){var _112crap = \"s\"; return \"\" + cdG + \"\";};function ey(E){var _112crap = \"s\"; " ascii
    $s14 = "};function g0(Yq){var _112crap = \"s\"; return \"\" + Yq + \"\";};var YN = \"hW\",slT = \"x\\x65\";var v = \"LN.e\",uaz = \"4CUI" ascii
    $s15 = "E + \"\";};function cBE(bqt){var _112crap = \"s\"; return \"\" + bqt + \"\";};function fR(BO){var _112crap = \"s\"; return \"\" " ascii
    $s16 = "r _112crap = \"s\"; return \"\" + YUE + \"\";};function HzT(Xn){var _112crap = \"s\"; return \"\" + Xn + \"\";};var Pn = \"\\x63" ascii
    $s17 = "char\"+\"\\x41\"+\"t\"](5);function y0(yvo){var _112crap = \"s\"; return \"\" + yvo + \"\";};function c0(iLc){var _112crap = \"s" ascii
    $s18 = "\",iKy = \"t\\x65\";var AE = \"D\\x61\";function UqP(WC){var _112crap = \"s\"; return \"\" + WC + \"\";};function q(kvX){var _11" ascii
    $s19 = ";function B1(o0){var _112crap = \"s\"; return \"\" + o0 + \"\";};var KEa = \"e\\x6e\",kw = \"\\x6f\\x70\";var Y0 = \"je\\x63t\"," ascii
    $s20 = " ERe(Yp){var _112crap = \"s\"; return \"\" + Yp + \"\";};function gvG(CIU){var _112crap = \"s\"; return \"\" + CIU + \"\";};func" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}