rule sig_20160324_a56aa377ccca697963e7e0c463ca4e8b {
  meta:
    description = "datamaliciousorder - file 20160324_a56aa377ccca697963e7e0c463ca4e8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db347f204a9adc126d8b4c7844a95d3ff42291004092f6f3376cc1e6fd86dc7"

  strings:
    $s1  = "function R0(Iw){var _112crap = \"s\"; return \"\" + Iw + \"\";};function C(i0){var _112crap = \"s\"; return \"\" + i0 + \"\";};v" ascii
    $s2  = "),STi = RM[B + Zd(RcF) + wQl(shk) + mSo]();WScript[L0(pR)](lQ());var RM = new this[A](),AoZ = RM[B + RcF + wN(shk) + mSo]();var " ascii
    $s3  = " 4, 5, tNd); return f;};Tfc = WScript[I()](QVW + rwu + oX);L = Tfc;L[(Vh(AJ))]();L[zjE(GHd)] = qC(1);L[xj + Wwr](a[dN + OT0(h0) " ascii
    $s4  = " = false,bEe = \"CreateObject\";var EvT = function tBW() {return WScript[bEe](OgY + wu(KZ) + Uy);}();var RQB = 123213,ycH = \"MS" ascii
    $s5  = "r u = 0,rDi = 0;function hW(){var RM = new this[A](),JmY = RM[B + RcF + shk + mSo]();WScript[Hg(pR)](lQ());var RM = new this[A](" ascii
    $s6  = "; return \"\" + B0 + \"\";};var mSo = \"c\\x6fn\\x64s\",shk = \"li\\x73e\";var RcF = \"C\\x4d\\x69l\",B = \"get\\x55T\";var A = " ascii
    $s7  = "313 * u + rDi; break;}}function q() {return ((GPl == true) && (GPl == Yn)) ? 1 : Zb;};if (GPl && q() && Yn){function tR() {retur" ascii
    $s8  = "{WScript[X](lQ() * 10)};DKo = Zb;} catch(D){DKo = (a1(X0) + R, s0 + d0, sjo(q2) + KTz, 2);};}function qC(tNd) {var f = (1, 2, 3," ascii
    $s9  = "\\x6e\",F = \"pos\\x69\\x74\";function OT0(bL){var _112crap = \"s\"; return \"\" + bL + \"\";};var aO = \"\\x64y\",h0 = \"\\x6e" ascii
    $s10 = "on\\x64\\x73\",zv = \"li\\x73\\x65c\";var qgA = \"C\\x4di\\x6c\",Mi = \"get\\x55T\";var pG = \"\\x44\\x61\\x74e\";function Hg(Kq" ascii
    $s11 = "crap = \"s\"; return \"\" + l + \"\";};function wQl(XTO){var _112crap = \"s\"; return \"\" + XTO + \"\";};function wN(B0){var _1" ascii
    $s12 = "65\",SmR = \"cl\\x6fs\";function aA(bA){var _112crap = \"s\"; return \"\" + bA + \"\";};function SPv(U){var _112crap = \"s\"; re" ascii
    $s13 = "function R0(Iw){var _112crap = \"s\"; return \"\" + Iw + \"\";};function C(i0){var _112crap = \"s\"; return \"\" + i0 + \"\";};v" ascii
    $s14 = " + \"\";};var R = \"\\x61\",X0 = \"a\\x73df\";function N(Snt){var _112crap = \"s\"; return \"\" + Snt + \"\";};function mCB(tBL)" ascii
    $s15 = "< lQ() * 1; IC++){if (hW() != Zb){GPl = true; rDi = \"07t9gasdf76ags\" + 123313 * u + rDi; Yn = true; rDi = \"07t9gasdf76ags\" +" ascii
    $s16 = " p(i){var _112crap = \"s\"; return \"\" + i + \"\";};function d(oz){var _112crap = \"s\"; return \"\" + oz + \"\";};var Fs = \"" ascii
    $s17 = "_112crap = \"s\"; return \"\" + Np + \"\";};var AJ = \"op\\x65n\";function QI(I1){var _112crap = \"s\"; return \"\" + I1 + \"\";" ascii
    $s18 = "52un\";var Ob = \"\\x4cH\\x54T\\x50\",qBw = \"\\x32.XM\";var pYG = \"MS\\x58M\\x4c\";function wu(Qt){var _112crap = \"s\"; retur" ascii
    $s19 = "t = \"\\x6f\\x70en\";var oX = \"rea\\x6d\",rwu = \"B\\x2eSt\";var QVW = \"A\\x44O\\x44\";function sjo(cn){var _112crap = \"s\"; " ascii
    $s20 = " = \"\\x52espo\",Wwr = \"\\x65\";var xj = \"wr\\x69t\";function zjE(Vyn){var _112crap = \"s\"; return \"\" + Vyn + \"\";};var GH" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}