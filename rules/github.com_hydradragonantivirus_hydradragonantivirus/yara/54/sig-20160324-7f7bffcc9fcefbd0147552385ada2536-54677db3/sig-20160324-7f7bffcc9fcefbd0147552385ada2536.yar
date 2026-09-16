rule sig_20160324_7f7bffcc9fcefbd0147552385ada2536 {
  meta:
    description = "datamaliciousorder - file 20160324_7f7bffcc9fcefbd0147552385ada2536.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eecf31af0ee2549225f886ba9bce8a46b82fc240a4c5f8bfb758fd5a0dac58d"

  strings:
    $s1  = "eOb\\x6a\\x65\";var f = \"\\x43r\\x65a\\x74\",U = false;var QBj = \"CreateObject\",bE = function NDO() {return WScript[QBj](j + " ascii
    $s2  = ") {return bE[Ez(F0) + au(NB) + H0 + NoH(Um) + jsR + N0](n + b0) + T0 + k0(Bkn) + X;}; k = D(); ofV = WScript[QBj](k); var A = 1;" ascii
    $s3  = ", 4, 5, ME); return sUL;};at = WScript[c()](G + Wwh(Ov) + w0);k = at;k[(smn(J1))]();k[th(Uc0)] = iz(1);k[KTb + YX](ofV[tt + pK(n" ascii
    $s4  = "oA());var lI = new this[xbc](),Uc = lI[J(dxO) + Ma(ou) + HL(sC) + w]();WScript[zyP](oA());var lI = new this[JMr(xbc)](),v = lI[d" ascii
    $s5  = "function HTs(ERS){var _112crap = \"s\"; return \"\" + ERS + \"\";};var ul = \"\\x65\",sx = \"\\x63\\x6cos\";var s = \"\\x65\",a " ascii
    $s6  = "] < 4 ) {WScript[WC](oA() * 10)};A = z;} catch(A0){A = (mUP(z1), Sf + hn, aU + ne(rT), 2);};}function iz(ME) {var sUL = (1, 2, 3" ascii
    $s7  = "{function oA(){return 22;};var L = 0,cAW = 0;function F(){var lI = new this[xbc](),c0 = lI[dxO + ou + sC + N(w)]();WScript[zyP](" ascii
    $s8  = "61fd\\x61f\";var hn = \"s\\x64f\",Sf = \"f\\x61df\\x61\";function mUP(kg){var _112crap = \"s\"; return \"\" + kg + \"\";};var z1" ascii
    $s9  = "){var _112crap = \"s\"; return \"\" + jTn + \"\";};function NoH(RmN){var _112crap = \"s\"; return \"\" + RmN + \"\";};var N0 = " ascii
    $s10 = " \"ea\\x6d\",Ov = \"\\x2eStr\";var G = \"A\\x44ODB\";function ne(dbj){var _112crap = \"s\"; return \"\" + dbj + \"\";};var rT = " ascii
    $s11 = ";var T0 = \"o85\\x38\",b0 = \"P\\x25\\x2f\";var n = \"%TE\\x4d\";function Ez(A1){var _112crap = \"s\"; return \"\" + A1 + \"\";}" ascii
    $s12 = "function HTs(ERS){var _112crap = \"s\"; return \"\" + ERS + \"\";};var ul = \"\\x65\",sx = \"\\x63\\x6cos\";var s = \"\\x65\",a " ascii
    $s13 = " \"\\x73en\\x64\";function Y0(X1){var _112crap = \"s\"; return \"\" + X1 + \"\";};function Bm(B0){var _112crap = \"s\"; return " ascii
    $s14 = " return \"\" + CU + \"\";};var Uc0 = \"\\x74\\x79pe\",hz = \"op\\x65n\";function Wwh(sF){var _112crap = \"s\"; return \"\" + sF " ascii
    $s15 = "1 = \"s\\x74a\\x74e\";var HA = \"rea\\x64\\x79\",IY = \"Sle\\x65\\x70\";function Cyo(cV){var _112crap = \"s\"; return \"\" + cV " ascii
    $s16 = "\"h\\x74tp\",R = \"\\x47\\x45T\";function X0(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function smn(BC){var _112crap = " ascii
    $s17 = " = \"s\"; return \"\" + H + \"\";};function J(az){var _112crap = \"s\"; return \"\" + az + \"\";};function Ma(SPi){var _112crap " ascii
    $s18 = "ar L0 = \"S\\x61veT\",zac = \"t\\x69\\x6fn\";var qZu = \"p\\x6f\\x73\\x69\";function pK(v2){var _112crap = \"s\"; return \"\" + " ascii
    $s19 = "n \"\" + SPi + \"\";};function HL(HG){var _112crap = \"s\"; return \"\" + HG + \"\";};var w = \"\\x6fnd\\x73\",sC = \"lis\\x65" ascii
    $s20 = " + BC + \"\";};var J1 = \"o\\x70en\";function k0(upP){var _112crap = \"s\"; return \"\" + upP + \"\";};var X = \"\\x2eex\\x65\"," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}