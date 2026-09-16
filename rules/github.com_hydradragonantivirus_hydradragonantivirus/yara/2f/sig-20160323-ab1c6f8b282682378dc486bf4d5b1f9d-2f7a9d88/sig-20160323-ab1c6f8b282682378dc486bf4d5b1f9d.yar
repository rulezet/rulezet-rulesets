rule sig_20160323_ab1c6f8b282682378dc486bf4d5b1f9d {
  meta:
    description = "datamaliciousorder - file 20160323_ab1c6f8b282682378dc486bf4d5b1f9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86093a4f39be4bff7cc8f50e8548ef37e72c9f3f51390d95b4f4f3429e7b18c9"

  strings:
    $s1  = "s[Niu(xx)](),shi = Pyr[I0(WaH) + sN + R0 + Dz1(a0) + d(bv) + MUF(Oy)]();WScript[x0(zW) + XJ(g1)](Cr());var Pyr = new this[ZD(xx)" ascii
    $s2  = "function wO(YX){var _112crap = \"s\"; return \"\" + YX + \"\";};var pzq = \"e\",G2 = \"c\\x6co\\x73\";function n1(uWW){var _112c" ascii
    $s3  = "Pyr = new this[xx](),mdb = Pyr[VX(WaH) + i0(sN) + WFJ(R0) + k1(a0) + bv + Oy]();WScript[T0(zW) + xR(g1)](Cr());var Pyr = new thi" ascii
    $s4  = " false,iB = function eSk() {return WScript[Dz(u) + sc(IxH) + pm(rXX) + xM(r) + s(T) + I(k) + DF(sNE)](CBJ(g) + J0(b) + LU(LzO) +" ascii
    $s5  = " = H[\"c\"+\"\\x68\"+\"arAt\"](0);var asJ = \"a\\x74\",z0 = xE[\"c\"+\"\\x68\"+\"arAt\"](0);function T0(n0){var _112crap = \"s\"" ascii
    $s6  = "nd = ZF[\"c\"+\"\\x68\"+\"arAt\"](2);var zuP = \"SX\",BH = \"\\x4d\";function JDb(UjC){var _112crap = \"s\"; return \"\" + UjC +" ascii
    $s7  = " \"esp\\x6fn\";var Pc = aR[\"c\"+\"\\x68\"+\"arAt\"](1);function vQv(qyw){var _112crap = \"s\"; return \"\" + qyw + \"\";};var d" ascii
    $s8  = " + ip(S) + n + Dz0(Mh);};function eO(Ni, Z){return Ni - Z;};function zHo(){return u + Xz(IxH) + Y(rXX) + r + T + m0(k) + sNE;};/" ascii
    $s9  = "313 * rQ + Q; sb = true; Q = \"07t9gasdf76ags\" + 123313 * rQ + Q; break;}}function YDv() {return ((U == sb) && (U == true)) ? t" ascii
    $s10 = "Run\";function CBJ(i){var _112crap = \"s\"; return \"\" + i + \"\";};function J0(qyY){var _112crap = \"s\"; return \"\" + qyY + " ascii
    $s11 = " T1(s3), true);};}function ysj(vBw) {var ZUG = (1, 2, 3, 4, 5, vBw); return ZUG;};rQ = (U) ? 14134 : 414234;kc = WScript[zHo()](" ascii
    $s12 = ") {WScript[HJ(zW) + SXu(g1)](Cr() * 10)};XDN = false;} catch(P){XDN = (B0(l0) + cu(qkP), pzI(TKO) + taf(BHQ), a1(K0) + Yj(qbD) +" ascii
    $s13 = ";var ux = \"MMEjRn\",o = \"%/\";var nbp = \"M\\x50\",nd = ux[\"c\"+\"\\x68\"+\"arAt\"](2);var r0 = \"\\x25T\";function oHW(pI){v" ascii
    $s14 = "n k1(vYs){var _112crap = \"s\"; return \"\" + vYs + \"\";};function I0(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};funct" ascii
    $s15 = "eturn \"\" + uWW + \"\";};function Ba(L4){var _112crap = \"s\"; return \"\" + L4 + \"\";};function OH(VYm){var _112crap = \"s\";" ascii
    $s16 = "function Ua(bKd){var _112crap = \"s\"; return \"\" + bKd + \"\";};function Z0(YE){var _112crap = \"s\"; return \"\" + YE + \"\";" ascii
    $s17 = "+ G0 + \"\";};function LY(z2){var _112crap = \"s\"; return \"\" + z2 + \"\";};function HSk(UT){var _112crap = \"s\"; return \"\"" ascii
    $s18 = " + C + \"\";};function TOC(M){var _112crap = \"s\"; return \"\" + M + \"\";};function SV(EAv){var _112crap = \"s\"; return \"\" " ascii
    $s19 = " D + \"\";};var Oy = \"nds\",bv = \"co\";var a0 = \"is\\x65\",R0 = \"M\\x69\\x6cl\";var sN = \"tUTC\",WaH = \"ge\";function Niu(" ascii
    $s20 = " return \"\" + hE + \"\";};function jwm(iXY){var _112crap = \"s\"; return \"\" + iXY + \"\";};function hp(g0){var _112crap = \"s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}