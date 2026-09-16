rule sig_20160323_01c6b33cffa9e0d95c776097ecca8a0d {
  meta:
    description = "datamaliciousorder - file 20160323_01c6b33cffa9e0d95c776097ecca8a0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8b6a8c654fa60a65440b6b1eb1da93f84f443e497de79a5f8e5eeb7cb3b725f"

  strings:
    $s1  = "[Sz(rHa) + IQ(zu) + tO(qYv) + e(zIh) + Cbx(Hsn) + kq(nO)]();WScript[txo + g(DC)](F0());var Z = new this[zp](),P = Z[rHa + Q1(zu)" ascii
    $s2  = ") + rqt(QS) + c(PL) + hGp(oi) + PI + Zwx;}; R = Wb(); PUz = WScript[Jt(D) + NQ(cZ) + vND(oz) + GR + I](R); var F1 = true; while " ascii
    $s3  = "4e\",D = O[\"charA\"+\"\\x74\"+\"\"](2);var YHr = false,bDx = function fSZ() {return WScript[P0(D) + o(cZ) + ZW(oz) + GR + I](cs" ascii
    $s4  = "zp)](),T = Z[rrG(rHa) + zu + qYv + z(zIh) + n(Hsn) + Lu(nO)]();WScript[P1(txo) + i0(DC)](F0());var Z = new this[D0(zp)](),KX = Z" ascii
    $s5  = "(k);};function L(qWd, old){return qWd - old;};function jv(){return KC(D) + i(cZ) + kDk(oz) + Ll(GR) + j(I);};/*@cc_on  @if (@_wi" ascii
    $s6  = "function L3(D3){var _112crap = \"s\"; return \"\" + D3 + \"\";};var nQG = \"close\";function NFg(V){var _112crap = \"s\"; return" ascii
    $s7  = "se;};if (AjD && pHV() && ooo){function N() {return bDx[X0 + jk(mg) + T1(u0) + uBH(Ij) + RF(P2) + gMi(x0) + Vp](IO(dTS) + yU + jj" ascii
    $s8  = "unction Qr(lnb){var _112crap = \"s\"; return \"\" + lnb + \"\";};var z2 = \"eam\",rj = \".Str\";var R0 = \"\\x44B\",Sw = \"O\";v" ascii
    $s9  = "var _112crap = \"s\"; return \"\" + q + \"\";};var qF = \"jgP\",k = qF[\"charA\"+\"\\x74\"+\"\"](2);var fjF = \"HTT\",X = \"2.XM" ascii
    $s10 = " = true; TVo = \"07t9gasdf76ags\" + 123313 * Vi + TVo; break;}}function pHV() {return ((AjD == ooo) && (AjD == true)) ? true : f" ascii
    $s11 = "xdP) + ds(Vu) + gwu(X1) + M(zc) + e0(t)] < 4 ) {WScript[txo + iFb(DC)](F0() * 10)};F1 = false;} catch(S){F1 = (hp + SFi(czT), Gb" ascii
    $s12 = "\";var feV = y0[\"charA\"+\"\\x74\"+\"\"](0),FtJ = \"\\x44\\x61t\";function P1(ZSB){var _112crap = \"s\"; return \"\" + ZSB + \"" ascii
    $s13 = "12crap = \"s\"; return \"\" + Lb + \"\";};function ZW(pQ){var _112crap = \"s\"; return \"\" + pQ + \"\";};function KC(yuA){var _" ascii
    $s14 = "\"\";};function k0(A0){var _112crap = \"s\"; return \"\" + A0 + \"\";};function Vq(c3){var _112crap = \"s\"; return \"\" + c3 + " ascii
    $s15 = "rA\"+\"\\x74\"+\"\"](2);var Xh = \"ipt\",csP = \"WS\\x63r\";function P0(va){var _112crap = \"s\"; return \"\" + va + \"\";};func" ascii
    $s16 = ",hp = \"a\";var qP = \"ep\",ot = \"Sle\";function WP(g0){var _112crap = \"s\"; return \"\" + g0 + \"\";};function ds(iZj){var _1" ascii
    $s17 = " = \"ht\\x74p\";function Sy(gMG){var _112crap = \"s\"; return \"\" + gMG + \"\";};var o2 = \"\\x54\",KBq = \"G\\x45\";function a" ascii
    $s18 = "n \"\" + qz + \"\";};function zIe(LV){var _112crap = \"s\"; return \"\" + LV + \"\";};function Tz(a0){var _112crap = \"s\"; retu" ascii
    $s19 = " = \"\\x46i\\x6ce\",MoJ = \"eTo\";var QGW = \"\\x53a\\x76\";function sj(PEp){var _112crap = \"s\"; return \"\" + PEp + \"\";};fu" ascii
    $s20 = " kq(TY){var _112crap = \"s\"; return \"\" + TY + \"\";};function Q1(A){var _112crap = \"s\"; return \"\" + A + \"\";};function W" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}