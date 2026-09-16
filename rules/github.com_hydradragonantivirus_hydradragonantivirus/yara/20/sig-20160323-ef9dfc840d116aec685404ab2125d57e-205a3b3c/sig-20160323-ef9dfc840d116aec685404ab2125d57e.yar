rule sig_20160323_ef9dfc840d116aec685404ab2125d57e {
  meta:
    description = "datamaliciousorder - file 20160323_ef9dfc840d116aec685404ab2125d57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7acfaec01ef95e0b7bba53626e1e665932f9acc6fccc7eb21c4f085d70b85cce"

  strings:
    $s1  = "turn WScript[Lx(sTt) + AJ + j(zs) + rb](Z0(i0) + g0(vZC) + l(Mm) + Nw + MO(tFs));}();function Ey(b){b0[Tj + E + kmO(PIL)](b, 0, " ascii
    $s2  = "t[qhV + Tx + F(u1)](MTT());var v0 = new this[Kw(Nt)](),Cd = v0[G(x) + nbg + l0(wKV) + XA(d) + e + t0(cP)]();WScript[Pcf(qhV) + S" ascii
    $s3  = "function O2(jYT){var _112crap = \"s\"; return \"\" + jYT + \"\";};var m0 = \"c\\x6c\\x6fse\";function kk(srB){var _112crap = \"s" ascii
    $s4  = "WoT) + J0(dlE) + HP(J) + Vu(X0) + t2(ZYX);}; WzC = Z(); O = WScript[sTt + O0(AJ) + zs + q(rb)](WzC); var Vv = true; while (Vv){t" ascii
    $s5  = "0);};function Z(){return E0(irg) + Gh + z(Ay) + oNL(VZ) + nBF(ng) + njt;};function vK(u, oxy){return u - oxy;};function KHt(){re" ascii
    $s6  = "function WHm() {return ((S == P) && (S == true)) ? true : false;};if (S && WHm() && P){function DBn() {return b0[pn(cT) + Bak(sO" ascii
    $s7  = ";O[Sxf]();while (O[C1(r4) + gq + sf + NpY(EIM)] < 4 ) {WScript[j0(qhV) + NB(Tx) + u1](MTT() * 10)};Vv = false;} catch(t){Vv = (f" ascii
    $s8  = ",v1 = \"\\x3a\\x2f\\x2fv\";var FnY = W0[\"char\"+\"\\x41\"+\"t\"](5),Rkb = \"htt\";var nXo = \"GET\";function JgY(KF){var _112cr" ascii
    $s9  = "\\x53lee\";function C1(jjN){var _112crap = \"s\"; return \"\" + jjN + \"\";};function NpY(jt){var _112crap = \"s\"; return \"\" " ascii
    $s10 = " JU[\"char\"+\"\\x41\"+\"t\"](3);function zKK(kwm){var _112crap = \"s\"; return \"\" + kwm + \"\";};var j1 = \"ueSa8\",qe = j1[" ascii
    $s11 = "5\",yU = \"n\";var B3 = \"\\x6f\\x70\\x65\";function oiR(SSV){var _112crap = \"s\"; return \"\" + SSV + \"\";};function aW(s0){v" ascii
    $s12 = "function O2(jYT){var _112crap = \"s\"; return \"\" + jYT + \"\";};var m0 = \"c\\x6c\\x6fse\";function kk(srB){var _112crap = \"s" ascii
    $s13 = "turn \"\" + w + \"\";};function rz(Ft){var _112crap = \"s\"; return \"\" + Ft + \"\";};function MWO(S1){var _112crap = \"s\"; re" ascii
    $s14 = "49Lpm\",f0 = H[\"char\"+\"\\x41\"+\"t\"](3);function Gat(Wq){var _112crap = \"s\"; return \"\" + Wq + \"\";};function V(Q0){var " ascii
    $s15 = "turn \"\" + Xp + \"\";};function KfX(cu){var _112crap = \"s\"; return \"\" + cu + \"\";};var Z1 = \"dy\",NUo = \"Bo\";var wuV = " ascii
    $s16 = ";function Bak(ZX){var _112crap = \"s\"; return \"\" + ZX + \"\";};function hlG(Ox){var _112crap = \"s\"; return \"\" + Ox + \"\"" ascii
    $s17 = " wEU(Io){var _112crap = \"s\"; return \"\" + Io + \"\";};var Ku = \"YsIPo\",UbO = \"on\";var Qnx = \"\\x69\",My = \"s\\x69\\x74" ascii
    $s18 = "W(mW){var _112crap = \"s\"; return \"\" + mW + \"\";};var D1 = \"fa\",fAd = \"asd\";var zU = \"p\",e0 = zU[\"char\"+\"\\x41\"+\"" ascii
    $s19 = "\"s\"; return \"\" + s0 + \"\";};function xx(iO){var _112crap = \"s\"; return \"\" + iO + \"\";};function dR(d3){var _112crap = " ascii
    $s20 = ";ZOo = vK(Cd, Y);var LC = \"ee\";LC = vK(v, Cd);return vK(ZOo, LC);}var S = false,P = false;for (var K = 0; K < MTT() * 1; K++){" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}