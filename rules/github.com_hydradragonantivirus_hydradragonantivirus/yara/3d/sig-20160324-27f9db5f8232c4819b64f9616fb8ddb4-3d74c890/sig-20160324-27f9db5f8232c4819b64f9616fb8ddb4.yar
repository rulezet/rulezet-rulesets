rule sig_20160324_27f9db5f8232c4819b64f9616fb8ddb4 {
  meta:
    description = "datamaliciousorder - file 20160324_27f9db5f8232c4819b64f9616fb8ddb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56efe0d2b155d72f14aa93d317678d33f243b42e86a19ad9a8576be6a946c321"

  strings:
    $s1  = "var hJC = \"c\\x6cose\";function sa(ni){var _112crap = \"s\"; return \"\" + ni + \"\";};function on(J){var _112crap = \"s\"; ret" ascii
    $s2  = " 4, 5, HRH); return WO;};fDC = (Ug) ? 14134 : 414234;wU = WScript[hLR()](zT(iE) + SD(yE) + K1(AO) + i2);tdU = wU;DyU = (GG) ? fD" ascii
    $s3  = "n0(Ojb)]();while (YLD[m1(Fh) + UT(nmY) + Il(GGW) + L0] < 4 ) {WScript[flJ + y2(nwe) + OH(XP) + byb(Plp)](O() * 10)};I = false;} " ascii
    $s4  = " new this[O0(led)](),a = KEz[xv(G) + p + zVT + K(Q) + t0 + z(NK) + W1 + q(HzJ)]();WScript[pD(flJ) + tmj0(nwe) + F(XP) + Plp](O()" ascii
    $s5  = ");var KEz = new this[kM(led)](),MWs = KEz[ty(G) + P(p) + zVT + njA(Q) + y1(t0) + G0(NK) + b(W1) + HzJ]();WScript[flJ + nwe + XP " ascii
    $s6  = " \"eO\\x62j\\x65\";var rD = \"\\x61t\",D0 = \"Cr\\x65\";var DRb = false,mq = function Ce() {return WScript[k(D0) + Xz(rD) + Hb(H" ascii
    $s7  = "PRZ) + LDK(uN);}; tdU = hk(); YLD = WScript[tw(D0) + vl(rD) + HWK + cME(yDX)](tdU); var I = true; while (I){try {YLD[T1 + AA + Z" ascii
    $s8  = "= \"\\x6c\";var Q = \"\\x69l\",zVT = \"M\";var p = \"C\",G = \"getUT\";function O0(XAV){var _112crap = \"s\"; return \"\" + XAV " ascii
    $s9  = " mLI(Xk) + GNU(uw);};function D(Any, HY){return Any - HY;};function hLR(){return DVB(D0) + ZkD(rD) + vX(HWK) + N(yDX);};/*@cc_on" ascii
    $s10 = "+ DyU; break;}}function ShS() {return ((Ug == GG) && (Ug == true)) ? true : false;};if (Ug && ShS() && GG){function uHH() {retur" ascii
    $s11 = "\\x42o\";var p1 = \"s\\x65\",KVe = \"\\x65s\\x70o\\x6e\";var VEF = \"R\";function wJk(al){var _112crap = \"s\"; return \"\" + al" ascii
    $s12 = "12crap = \"s\"; return \"\" + Pr + \"\";};var xs = \"ScSuSm\",nTi = \"KMilefNEQO\";var Plp = \"ep\",XP = nTi[\"cha\"+\"\\x72\"+" ascii
    $s13 = " \"\\x70t.S\",gQm = \"ri\";var N0 = \"W\\x53\\x63\";function k(W){var _112crap = \"s\"; return \"\" + W + \"\";};function Xz(t){" ascii
    $s14 = "(cpD(N0) + SW(gQm) + Z + xY(C) + lN);}();function YBQ(j){mq[sf(mCj)](j, 0, 0);};function hk(){return cF(wmq) + vJ(W0) + HI(ND) +" ascii
    $s15 = "p = \"s\"; return \"\" + mD + \"\";};function Kyq(fD){var _112crap = \"s\"; return \"\" + fD + \"\";};function z2(Kxb){var _112c" ascii
    $s16 = " = \"M\\x50\\x25/\",k1 = \"%\\x54E\";function WGD(A0){var _112crap = \"s\"; return \"\" + A0 + \"\";};function z0(P0){var _112cr" ascii
    $s17 = "\"\\x66a\",M0 = \"asd\";var pTY = \"\\x6c\\x65ep\",Bu0 = \"\\x53\";function m1(F1){var _112crap = \"s\"; return \"\" + F1 + \"\"" ascii
    $s18 = "dys\\x74\";var nmY = \"\\x61\",Fh = \"re\";function W2(oWg){var _112crap = \"s\"; return \"\" + oWg + \"\";};function Wn0(XP0){v" ascii
    $s19 = "NJ){var _112crap = \"s\"; return \"\" + NJ + \"\";};function Hgt(zi){var _112crap = \"s\"; return \"\" + zi + \"\";};var xh = \"" ascii
    $s20 = "var G1 = \"fdaf\",aJ = LI[\"cha\"+\"\\x72\"+\"At\"](5);function v(gT){var _112crap = \"s\"; return \"\" + gT + \"\";};function U" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}