rule sig_20160323_231a35fd6fd22e5156e3238496eeaca3 {
  meta:
    description = "datamaliciousorder - file 20160323_231a35fd6fd22e5156e3238496eeaca3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f11f6d2e7333ea7a41f4d254806d14c6e7fe57b788948fdcfae0154158e94dba"

  strings:
    $s1  = "function kIb(ZLi){var _112crap = \"s\"; return \"\" + ZLi + \"\";};function b1(cP){var _112crap = \"s\"; return \"\" + cP + \"\"" ascii
    $s2  = "KAF + OnC(Y0)](),eN = nAC[o0 + IEE(i0) + X0 + RRF + B(d0) + oZ(udc)]();WScript[N0(V)](h());var nAC = new this[Kjb(c) + x(KAF) + " ascii
    $s3  = " QY = Wa(); v1 = WScript[ag(Fq) + H(NT) + W0](QY); var E = true; while (E){try {v1[eYJ(Aw) + Y1](ejN(Qd) + rI, pmi(SSL) + y3 + r" ascii
    $s4  = "k0(KAF) + dYA(Y0)](),v = nAC[o0 + t(i0) + xi(X0) + hx(RRF) + PxJ(d0) + NH(udc)]();WScript[O0(V)](h());var nAC = new this[G(c) + " ascii
    $s5  = "W0 = \"bject\",NT = \"eat\\x65O\";var Fq = \"C\\x72\",Xpr = false;var v0 = function rho() {return WScript[E0(Fq) + UqP(NT) + Y(W" ascii
    $s6  = "io\";var E1 = \".com\",mN = \"s\\x75lt\";var WNU = \"c\\x6fn\",kaH = \"-\";var y3 = \"\\x3a\\x2f/\\x76\\x6c\",SSL = \"h\\x74t\\x" ascii
    $s7  = "(re) + o(X) + TbM(kz) + P(F0);};function LkI(N, EO){return N - EO;};function dC(){return eym(Fq) + NT + W0;};/*@cc_on  @if (@_wi" ascii
    $s8  = "o) && (zHc == true)) ? true : false;};if (zHc && Dec() && Uo){function W() {return v0[h1(dcd) + nFQ(j1) + Z1(r) + edW(JS) + X1(J" ascii
    $s9  = "2(lwO)] < 4 ) {WScript[Z(V)](h() * 10)};E = false;} catch(Iv){E = (BX(HpK) + k1(zYV), W1(atz) + c0(Vu) + R1(a1) + os(jc), SrD(J0" ascii
    $s10 = "\\x6f\";var RRF = \"l\\x69\",X0 = \"\\x4di\\x6c\";var i0 = \"UTC\",o0 = \"\\x67\\x65\\x74\";function k0(h0){var _112crap = \"s\"" ascii
    $s11 = "\\x61\",q3 = \"\\x61\";var J0 = \"afd\";function W1(Got){var _112crap = \"s\"; return \"\" + Got + \"\";};function c0(sss){var _" ascii
    $s12 = "};function mP(hSx){var _112crap = \"s\"; return \"\" + hSx + \"\";};function MQ(e){var _112crap = \"s\"; return \"\" + e + \"\";" ascii
    $s13 = "r a0 = \"\\x6a\\x65ct\",UL = \"\\x65O\\x62\";var y2 = \"Cre\\x61t\";function ZmM(f){var _112crap = \"s\"; return \"\" + f + \"\"" ascii
    $s14 = "p = \"s\"; return \"\" + UDB + \"\";};function N0(P0){var _112crap = \"s\"; return \"\" + P0 + \"\";};function Z(j){var _112crap" ascii
    $s15 = "+ \"\";};function q1(azF){var _112crap = \"s\"; return \"\" + azF + \"\";};function kSh(x1){var _112crap = \"s\"; return \"\" + " ascii
    $s16 = "0(kaH) + kMp(WNU) + RRm(mN) + q1(E1) + kCz + kSh(QY0) + y4(d2), false);v1[WO0(Uk) + x2(T) + q2]();while (v1[zb(H1) + vUW(lm) + j" ascii
    $s17 = "; return \"\" + Id + \"\";};var Zd = \"\\x65\",lak = \"X.e\\x78\";var xO = \"\\x35XI\",Sv = \"\\x731\";var z0 = \"i\",d1 = \"Qxv" ascii
    $s18 = "x50%\";var cDM = \"\\x54EM\",NE = \"%\";function h1(sT){var _112crap = \"s\"; return \"\" + sT + \"\";};function nFQ(RwH){var _1" ascii
    $s19 = "\"\" + a + \"\";};function X1(oBN){var _112crap = \"s\"; return \"\" + oBN + \"\";};function O1(C){var _112crap = \"s\"; return " ascii
    $s20 = "\"\" + v3 + \"\";};var jc = \"\\x64\\x66\",a1 = \"\\x66a\\x73\";var Vu = \"\\x64\",atz = \"f\\x61\";function BX(MWj){var _112cra" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}