rule sig_20160323_39fd02c6fe2efa784752a2bd85cf015f {
  meta:
    description = "datamaliciousorder - file 20160323_39fd02c6fe2efa784752a2bd85cf015f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c8ed0cdc4aa90139663e028e0b3225bd3aa03c7fe482b4b4a516794033d36b"

  strings:
    $s1  = "function bfu(z){var _112crap = \"s\"; return \"\" + z + \"\";};function N2(pAk){var _112crap = \"s\"; return \"\" + pAk + \"\";}" ascii
    $s2  = " \"a\\x73our\";var zeJ = Suy[\"c\"+\"\\x68\"+\"arAt\"](2),vA = \"s\";var Hr = \"//\\x73a\",qEM = \"\\x68\\x74tp:\";function i0(D" ascii
    $s3  = "\"\\x6a\\x65\";var RNl = \"b\",eDN = \"at\\x65O\";var HrK = \"Cre\",CKi = false;var iSa = function r() {return WScript[te(HrK) +" ascii
    $s4  = "FF = new this[Hh(cYF) + L(MZ)](),VD = BFF[AJb(P) + R0(xtJ) + pl(dE) + pnB(sVh) + W0(jH) + BKF(Bda)]();WScript[N + GZ(Pl) + DFN(G" ascii
    $s5  = ");}; C = y(); t = WScript[b(HrK) + xp(eDN) + RNl + q(TWK) + BM(DZf)](C); var sxh = true; while (sxh){try {t[q1(Z1) + j1(Hx)](p0 " ascii
    $s6  = "E)](T());var BFF = new this[oa0(cYF) + hjE(MZ)](),Z = BFF[C0(P) + eZ(xtJ) + o3(dE) + mTY(sVh) + o4(jH) + c0(Bda)]();WScript[BiT(" ascii
    $s7  = "B(Zp0){var _112crap = \"s\"; return \"\" + Zp0 + \"\";};var FJ = \"u2e39s\",v1 = \"3e\";var GI = v1[\"c\"+\"\\x68\"+\"arAt\"](1)" ascii
    $s8  = " oG[\"c\"+\"\\x68\"+\"arAt\"](2),TLq = \"asd\";var qm = \"\\x53leep\";function y3(Ei){var _112crap = \"s\"; return \"\" + Ei + " ascii
    $s9  = " Hl + \"\";};var VZz = \"oix\",CVJ = \"n\";var t1 = \"\\x6f\",I0 = VZz[\"c\"+\"\\x68\"+\"arAt\"](1);var cD = \"\\x6fsi\\x74\",j2" ascii
    $s10 = "){var _112crap = \"s\"; return \"\" + q4 + \"\";};var nrb = \"rXifzY\",g1 = \"pfp5CT\";var qh0 = g1[\"c\"+\"\\x68\"+\"arAt\"](1)" ascii
    $s11 = " = \"adfas\",MWp = nrb[\"c\"+\"\\x68\"+\"arAt\"](3);function SFw(Ti){var _112crap = \"s\"; return \"\" + Ti + \"\";};function b1" ascii
    $s12 = "rap = \"s\"; return \"\" + HRn + \"\";};var LR = \"LscJ9\",U1 = \"nd\";var y2 = \"e\",Q0 = LR[\"c\"+\"\\x68\"+\"arAt\"](1);funct" ascii
    $s13 = "8\"+\"arAt\"](5);var NBj = \"cl\\x6f\";function PR(Meh){var _112crap = \"s\"; return \"\" + Meh + \"\";};function Ba(uIq){var _1" ascii
    $s14 = "\"+\"\\x68\"+\"arAt\"](5),Pl = IVP[\"c\"+\"\\x68\"+\"arAt\"](5);var N = \"Sle\";function AJb(o2){var _112crap = \"s\"; return \"" ascii
    $s15 = "eturn hw(ea) + tt(qVb) + n0(tj);};function iRg(o, vr){return o - vr;};function D(){return HrK + Nu(eDN) + RNl + TWK + n(DZf);};/" ascii
    $s16 = " sGv + y0; break;}}function AGN() {return ((xql == VQr) && (xql == true)) ? true : false;};if (xql && AGN() && VQr){function I()" ascii
    $s17 = "+ U1]();while (t[y3(Po) + XZ + PT] < 4 ) {WScript[N + Pl + GE](T() * 10)};sxh = false;} catch(O){sxh = (SFw(TLq) + b1(xfX) + cHi" ascii
    $s18 = "jH = \"\\x6e\\x64\";var sVh = \"\\x73\\x65\\x63\\x6f\",dE = \"\\x69l\\x6ci\";var xtJ = \"\\x54\\x43\\x4d\",P = \"getU\";function" ascii
    $s19 = "b\";var bF = \"\\x61t\",ESj = \"\\x65\";var o1 = \"r\",jxM = \"\\x43\";function hw(LWZ){var _112crap = \"s\"; return \"\" + LWZ " ascii
    $s20 = " l0(Wwk){var _112crap = \"s\"; return \"\" + Wwk + \"\";};function CiF(CD){var _112crap = \"s\"; return \"\" + CD + \"\";};var B" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}