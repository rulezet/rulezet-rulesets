rule sig_20160324_3e2f1014b89507fd42f6a98ea0a21a61 {
  meta:
    description = "datamaliciousorder - file 20160324_3e2f1014b89507fd42f6a98ea0a21a61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e44837228c02bf9f6025b315f1b17d6c3ab166a079c39fab69fd6aa102b76e"

  strings:
    $s1  = "se,j = \"CreateObject\";var pz = function x() {return WScript[j](M + GAm + ul);}();var ZsU = 123213,sLS = \"MSXML2.XMLHTTP\";var" ascii
    $s2  = "function c(tj){var _112crap = \"s\"; return \"\" + tj + \"\";};var NaF = \"\\x65\",gT = \"\\x63lo\\x73\";var kn = \"\\x65\",EDE " ascii
    $s3  = "= 0;function TlU(){var uTL = new this[e](),hyL = uTL[u + Q(qbO) + ur + xBp(t0) + k]();WScript[E(iKe)](Uf());var uTL = new this[e" ascii
    $s4  = "1 + Eq + j2 + qe + PZ(e0) + kZM](B + itu) + gO + P0 + KUe + G0(bC);}; Mlc = LZT(); bz = WScript[j](Mlc); var Hwi = 1; while (Hwi" ascii
    $s5  = ", 4, 5, MEU); return zEV;};UVD = WScript[h()](wrr(hWM) + mG + xn);Mlc = UVD;Mlc[(AQ)]();Mlc[Fk] = H(1);Mlc[ED](bz[vlQ(XW) + CES " ascii
    $s6  = "](),ZDj = uTL[KX(u) + qbO + ur + t0 + k]();WScript[iKe](Uf());var uTL = new this[e](),Vs = uTL[u + qbO + w(ur) + t0 + k]();var E" ascii
    $s7  = "= 2123213,sIZ = 0;function Tqi(G){pz[guV(DW)](G, sIZ, sIZ);};function LZT(){return sLS;};function YWW(qRx, HE){return qRx - HE;}" ascii
    $s8  = "61m\",mG = \"\\x42.Str\";var hWM = \"AD\\x4fD\";function mME(g){var _112crap = \"s\"; return \"\" + g + \"\";};var PrJ = \"\\x61" ascii
    $s9  = "Er + XE; break;}}function rLl() {return ((ee == true) && (ee == N)) ? 1 : sIZ;};if (ee && rLl() && N){function XU() {return pz[j" ascii
    $s10 = "\\x6c\";var Sw = \"\\x53ave\",Cd = \"ti\\x6fn\";var lUR = \"p\\x6f\\x73\\x69\";function vlQ(k1){var _112crap = \"s\"; return \"" ascii
    $s11 = "p = \"s\"; return \"\" + ZP + \"\";};function KX(Xt){var _112crap = \"s\"; return \"\" + Xt + \"\";};function w(kB){var _112crap" ascii
    $s12 = "i\\x74\\x65\";var Fk = \"typ\\x65\",WwV = \"\\x6f\\x70\\x65\\x6e\";function wrr(y){var _112crap = \"s\"; return \"\" + y + \"\";" ascii
    $s13 = "function c(tj){var _112crap = \"s\"; return \"\" + tj + \"\";};var NaF = \"\\x65\",gT = \"\\x63lo\\x73\";var kn = \"\\x65\",EDE " ascii
    $s14 = "0 = \"\\x4arrCq\",gO = \"Pwj\\x381\";var itu = \"%\\x2f\",B = \"%\\x54EMP\";function PZ(O){var _112crap = \"s\"; return \"\" + O" ascii
    $s15 = "f() * 1; t++){if (TlU() != sIZ){ee = true; XE = \"07t9gasdf76ags\" + 123313 * Er + XE; N = true; XE = \"07t9gasdf76ags\" + 12331" ascii
    $s16 = "6\";function af(DOp){var _112crap = \"s\"; return \"\" + DOp + \"\";};function D(tf){var _112crap = \"s\"; return \"\" + tf + \"" ascii
    $s17 = "){try {bz[AQ](e1, MR + si + cMw + qJG(H0) + T + zJ(Vn), false);bz[grK]();d = \"Sleep\";while (bz[miQ(woW) + OUT + RJk] < 4 ) {WS" ascii
    $s18 = "ction IF(xJs){var _112crap = \"s\"; return \"\" + xJs + \"\";};var Dx = \"Bo\\x64y\",CES = \"\\x6fn\\x73\\x65\";var XW = \"Re\\x" ascii
    $s19 = "rn \"\" + kB + \"\";};var k = \"\\x64s\",t0 = \"\\x65\\x63on\";var ur = \"ll\\x69s\",qbO = \"TC\\x4di\";var u = \"ge\\x74U\",e =" ascii
    $s20 = "n \"\" + k0 + \"\";};var iKe = \"S\\x6cee\\x70\";function Q(jvn){var _112crap = \"s\"; return \"\" + jvn + \"\";};function xBp(Z" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}