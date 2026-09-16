rule sig_20160323_abb83a07a50fffe070daeddeb914ec8d {
  meta:
    description = "datamaliciousorder - file 20160323_abb83a07a50fffe070daeddeb914ec8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4509099f8684385dd814b9a016245708655adb69a8042f689f3a1c8ea42d7da"

  strings:
    $s1  = ";var x = new this[r0(d) + tL(Bl)](),eX = x[p0(cB) + NsO(r1) + X + HAg(d0) + On(V) + DJ(rmX) + iD(ssJ)]();WScript[Wtj + r2(MB) + " ascii
    $s2  = "vX), true);};}function Jv(DkL) {var c = (1, 2, 3, 4, 5, DkL); return c;};tA = (N) ? 14134 : 414234;m = WScript[u()](Vao(G0) + uT" ascii
    $s3  = "function B3(b1){var _112crap = \"s\"; return \"\" + b1 + \"\";};var W3 = \"ta6Tmemxisd\",Uez = W3[\"cha\"+\"\\x72\"+\"At\"](5);v" ascii
    $s4  = "() {return WScript[scC(w) + Wl(SfK) + Gn](eIv(Nj) + ix(poe) + mZ(wDM) + AqC(e0));}();function A(lF){e[vAR + pEf(lzD)](lF, 0, 0);" ascii
    $s5  = "{var x = new this[QPn(d) + D(Bl)](),Nc = x[Iq(cB) + r1 + X + A0(d0) + E(V) + p(rmX) + qTY(ssJ)]();WScript[Wtj + zo(MB) + G](K())" ascii
    $s6  = "nZ(); wV = WScript[ZrX(w) + n(SfK) + a(Gn)](IdO); var W = true; while (W){try {wV[qOJ(C) + jek(Y) + x0(LTZ)](yQY, C0(BK) + mum(R" ascii
    $s7  = "};function nZ(){return w0(uTb) + QF + YW(pHT) + P0;};function r(Dqj, b){return Dqj - b;};function u(){return zvT(w) + SfK + JQ(G" ascii
    $s8  = "el() {return ((N == hB) && (N == true)) ? true : false;};if (N && el() && hB){function J() {return e[mw + LRz + u0(Ndy) + ouz + " ascii
    $s9  = " \"\\x75rce\\x2e\",fwU = oRw[\"cha\"+\"\\x72\"+\"At\"](0);var p3 = \"a\\x73\\x74as\",RF = \"\\x70\\x3a//s\";var BK = \"htt\",yQY" ascii
    $s10 = " O0 + \"\";};function Bpt(nK){var _112crap = \"s\"; return \"\" + nK + \"\";};function r3(BC){var _112crap = \"s\"; return \"\" " ascii
    $s11 = "var u1 = \"%T\\x45\\x4d\";function u0(fnz){var _112crap = \"s\"; return \"\" + fnz + \"\";};function jg(KQ){var _112crap = \"s\"" ascii
    $s12 = "function B3(b1){var _112crap = \"s\"; return \"\" + b1 + \"\";};var W3 = \"ta6Tmemxisd\",Uez = W3[\"cha\"+\"\\x72\"+\"At\"](5);v" ascii
    $s13 = "G](K());var x = new this[c0(d) + wF(Bl)](),Sf = x[eJt(cB) + p1(r1) + X + Wt(d0) + I0(V) + e1(rmX) + a0(ssJ)]();var tA = \"cxA\";" ascii
    $s14 = "Re\\x73p\";function Tlq(cs){var _112crap = \"s\"; return \"\" + cs + \"\";};function yI(y0){var _112crap = \"s\"; return \"\" + " ascii
    $s15 = "var _112crap = \"s\"; return \"\" + Ei + \"\";};function ym(sZY){var _112crap = \"s\"; return \"\" + sZY + \"\";};var dBL = \"/" ascii
    $s16 = "var eq = \"pA9\",G = eq[\"cha\"+\"\\x72\"+\"At\"](0);var MB = \"\\x6cee\",Wtj = \"S\";function Iq(ez){var _112crap = \"s\"; retu" ascii
    $s17 = "ap = \"s\"; return \"\" + rxw + \"\";};var H1 = \"t\\x65\",be = \"ta\";var u3 = \"ys\",GFH = \"rea\\x64\";function Yk(qE){var _1" ascii
    $s18 = "s\";function brL(tTo){var _112crap = \"s\"; return \"\" + tTo + \"\";};function YY(iK){var _112crap = \"s\"; return \"\" + iK + " ascii
    $s19 = "+ KQ + \"\";};function c1(pYa){var _112crap = \"s\"; return \"\" + pYa + \"\";};function yUt(dT){var _112crap = \"s\"; return \"" ascii
    $s20 = "f1 = \"ope\";function Vao(Iz){var _112crap = \"s\"; return \"\" + Iz + \"\";};function uT(pA){var _112crap = \"s\"; return \"\" " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}