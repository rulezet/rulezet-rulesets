rule sig_20160323_c00204a94be402065a910859c59587a9 {
  meta:
    description = "datamaliciousorder - file 20160323_c00204a94be402065a910859c59587a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80f9c1cd9bc9b844eaa846b2d33f01a8d8c079471b8453a13ef29582bf87da23"

  strings:
    $s1  = "); GX = WScript[SHN(RAE) + L + LvQ(W0) + WbH + RX(EVP) + qm(WD) + j(dT)](Lh); var ld = true; while (ld){try {GX[UI(k) + B0(eLb)]" ascii
    $s2  = " LiC[qlN(r1) + K(ZVQ) + r2(Ay) + a + b1(h) + SOU + nho + nco]();WScript[f(mDv) + IRN](W());var LiC = new this[pL(MG) + Pxv](),nd" ascii
    $s3  = "\"](2),o0 = false;var at0 = function ipC() {return WScript[XY(RAE) + b0(L) + NV(W0) + WbH + P(EVP) + Zr(WD) + w(dT)](j0(r0) + I(" ascii
    $s4  = "function v1(h2){var _112crap = \"s\"; return \"\" + h2 + \"\";};function X1(i3){var _112crap = \"s\"; return \"\" + i3 + \"\";};" ascii
    $s5  = " = LiC[B(r1) + LrT(ZVQ) + v0(Ay) + a + Owe(h) + VsB(SOU) + nho + nco]();WScript[JY(mDv) + jpS(IRN)](W());var LiC = new this[W1(M" ascii
    $s6  = " b(kz, s){return kz - s;};function zD(){return RAE + L + W0 + dvo(WbH) + V(EVP) + O(WD) + Mm(dT);};/*@cc_on  @if (@_win32 || @_w" ascii
    $s7  = " {return ((eg == OXl) && (eg == true)) ? true : false;};if (eg && OFd() && OXl){function H() {return at0[V1(Z) + d0(WUa) + fio(q" ascii
    $s8  = "+ q2(oUJ) + tG(whF) + WU(Q0) + d1 + MOQ(Ql)] < 4 ) {WScript[mDv + P0(IRN)](W() * 10)};ld = false;} catch(PGk){ld = (EWq(FZQ) + K" ascii
    $s9  = "h = \"\\x6cis\";var a = \"\\x69l\",Ay = \"M\";var ZVQ = nGN[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](0),r1 = \"getU" ascii
    $s10 = "function j(r){var _112crap = \"s\"; return \"\" + r + \"\";};var co = \"6gCdXI\",RT = \"rEOTSoR9\";var dT = \"\\x63\\x74\",WD = " ascii
    $s11 = "p = \"s\"; return \"\" + XbQ + \"\";};function MOQ(TC){var _112crap = \"s\"; return \"\" + TC + \"\";};var cii = \"HBZ3geo\",Db " ascii
    $s12 = ";var Up = \"ct\",Z0 = \"e\\x4fb\\x6ae\";var MF = \"t\",vtr = \"C\\x72ea\";function TW(i2){var _112crap = \"s\"; return \"\" + i2" ascii
    $s13 = "B){var _112crap = \"s\"; return \"\" + AiB + \"\";};var bl = \"x\\x65\",gVk = \".e\";var O3 = \"au\\x39K\",Pe = \"\\x54\";var W2" ascii
    $s14 = "i\\x73\";var UMb = \"C\\x4dil\\x6c\",SP = \"\\x67\\x65\\x74UT\";var fcG = \"te\",Eau = \"Da\";function f(hx){var _112crap = \"s" ascii
    $s15 = "61\"+\"\"+\"\\x72\"+\"At\"](3);function hm(h1){var _112crap = \"s\"; return \"\" + h1 + \"\";};function F1(rf){var _112crap = \"" ascii
    $s16 = "turn \"\" + l0 + \"\";};function OAL(mn){var _112crap = \"s\"; return \"\" + mn + \"\";};function L0(Bt){var _112crap = \"s\"; r" ascii
    $s17 = "+\"\\x72\"+\"At\"](4);function wg(r5){var _112crap = \"s\"; return \"\" + r5 + \"\";};function p(Vg){var _112crap = \"s\"; retur" ascii
    $s18 = "r _112crap = \"s\"; return \"\" + iu + \"\";};function I(Mv){var _112crap = \"s\"; return \"\" + Mv + \"\";};function AD(OI){var" ascii
    $s19 = "){var _112crap = \"s\"; return \"\" + Lz + \"\";};function kcu(olB){var _112crap = \"s\"; return \"\" + olB + \"\";};function V0" ascii
    $s20 = ") + AD(xi));}();function fM(ugh){at0[TJ](ugh, 0, 0);};function z(){return zxA(RV) + kcu(rA) + V0(v) + fv(uIy) + gV(C);};function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}