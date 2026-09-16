rule sig_20160323_e6d0eea4be9d92617d381382e0eee9ff {
  meta:
    description = "datamaliciousorder - file 20160323_e6d0eea4be9d92617d381382e0eee9ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d95e8b956368b836fc861a48bf6a0a49a676f5419a0d51772628c8547ac8a65"

  strings:
    $s1  = "Cr\";var LC = false,NH = function sg() {return WScript[tMX + Coe(gU) + ab(zC) + Ua(x) + jd](Yo(xp) + rK(Y) + r(D) + vLm(Ya));}()" ascii
    $s2  = "function sj(H3){var _112crap = \"s\"; return \"\" + H3 + \"\";};function Tot(Z){var _112crap = \"s\"; return \"\" + Z + \"\";};f" ascii
    $s3  = " + PYr + R(eP) + ont(BR);}; dXY = LP(); Nj = WScript[UE(tMX) + XHy(gU) + zC + wQM(x) + Jy(jd)](dXY); var IY = true; while (IY){t" ascii
    $s4  = "t0(p) + J0(Zja) + xpW(Sr) + Rg(ocw) + X0(Eg0) + F(s) + b + Xo]();WScript[C(am) + r0(bF)](bxo());var Ebl = new this[Fj(XB) + DcZ(" ascii
    $s5  = "ku = \"get\\x55T\";function t(ZAP){var _112crap = \"s\"; return \"\" + ZAP + \"\";};function yM(DQ){var _112crap = \"s\"; return" ascii
    $s6  = " * QG + o; break;}}function LuW() {return ((Tib == oB) && (Tib == true)) ? true : false;};if (Tib && LuW() && oB){function u() {" ascii
    $s7  = "Q) + Cv]();while (Nj[Gt(rZ) + Nt + g2(c) + Wx(X3) + F0(v0)] < 4 ) {WScript[VRu(am) + q0(bF)](bxo() * 10)};IY = false;} catch(H){" ascii
    $s8  = "p = \"WS\\x63\\x72\";function Coe(Zo){var _112crap = \"s\"; return \"\" + Zo + \"\";};function ab(zT){var _112crap = \"s\"; retu" ascii
    $s9  = "var am = uGn[\"charA\"+\"\\x74\"+\"\"](3);function zAL(dBG){var _112crap = \"s\"; return \"\" + dBG + \"\";};function t0(b0){var" ascii
    $s10 = "\"\";};function R(bh){var _112crap = \"s\"; return \"\" + bh + \"\";};function ont(D2){var _112crap = \"s\"; return \"\" + D2 + " ascii
    $s11 = "2 + \"\";};function s1(RC){var _112crap = \"s\"; return \"\" + RC + \"\";};function T(fAx){var _112crap = \"s\"; return \"\" + f" ascii
    $s12 = "s\"; return \"\" + b0 + \"\";};function J0(W){var _112crap = \"s\"; return \"\" + W + \"\";};function xpW(NGo){var _112crap = \"" ascii
    $s13 = ")](bxo());var Ebl = new this[U(XB) + DwV(u1)](),ipH = Ebl[Dr(Eku) + D0(p) + GQr(Zja) + Sr + fYE(ocw) + gXa(Eg0) + TQ(s) + Bj(b) " ascii
    $s14 = "= \"s\"; return \"\" + O3 + \"\";};function YPz(Ue){var _112crap = \"s\"; return \"\" + Ue + \"\";};function b5(wNX){var _112cra" ascii
    $s15 = "ry {Nj[WU(U0) + ufs](k0(Ugp) + YPp(CbG), Fmq(Ql) + YPz(eC) + b5(P) + hui(Ms) + P0(KR) + s1(rkf) + T(d) + XAX(Y1), false);Nj[KD(M" ascii
    $s16 = "\" + NGo + \"\";};function Rg(pkp){var _112crap = \"s\"; return \"\" + pkp + \"\";};function X0(t1){var _112crap = \"s\"; return" ascii
    $s17 = "vH){var _112crap = \"s\"; return \"\" + vvH + \"\";};var ocN = \"e\",K4 = \"o\\x73\";var mN = \"\\x63\\x6c\";function Al(vqy){va" ascii
    $s18 = "\"\";};function F(Jua){var _112crap = \"s\"; return \"\" + Jua + \"\";};function eKV(mov){var _112crap = \"s\"; return \"\" + mo" ascii
    $s19 = "gM){var _112crap = \"s\"; return \"\" + gM + \"\";};function b2(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};function y0(" ascii
    $s20 = "urn \"\" + wNX + \"\";};function hui(M0){var _112crap = \"s\"; return \"\" + M0 + \"\";};function P0(E2){var _112crap = \"s\"; r" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}