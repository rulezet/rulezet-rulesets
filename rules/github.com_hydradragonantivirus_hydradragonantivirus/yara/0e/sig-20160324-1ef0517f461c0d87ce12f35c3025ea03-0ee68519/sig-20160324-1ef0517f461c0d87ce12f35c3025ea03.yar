rule sig_20160324_1ef0517f461c0d87ce12f35c3025ea03 {
  meta:
    description = "datamaliciousorder - file 20160324_1ef0517f461c0d87ce12f35c3025ea03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b95bb9ea5debf0b88e96d5421e0fccd3bed98295164835f231c7231b17b02d68"

  strings:
    $s1  = "var Nf = \"clo\\x73e\";function jj(nPl){var _112crap = \"s\"; return \"\" + nPl + \"\";};function Q2(ZSj){var _112crap = \"s\"; " ascii
    $s2  = "eturn \"\" + Ml + \"\";};var L = \"%/\",Tx = \"%TEMP\";function NA(z1){var _112crap = \"s\"; return \"\" + z1 + \"\";};function " ascii
    $s3  = " WScript[m(ukK) + e0(k) + xo(e) + Xib + GT(iC)](Pg(I) + N0 + ItH(Wj) + b + jlw(Z) + c(ga));}();function CqS(hI){zC[ckB](hI, 0, 0" ascii
    $s4  = ") + w2]();WScript[OK(Sd0) + KEi(xo0) + iH(wtn)](Dic());var MP = new this[nId(Yb) + lu(bEd)](),bMW = MP[LV(Sd) + Rw + W0(vB) + vM" ascii
    $s5  = "bg(w2)]();WScript[Sd0 + u(xo0) + v1(wtn)](Dic());var MP = new this[Ifc(Yb) + D(bEd)](),DR = MP[Sd + N1(Rw) + R0(vB) + D0 + zD(Aw" ascii
    $s6  = " BPw(o0) + mZc(jm) + NUO + s2(DU);}; Ud = s(); iAp = WScript[q(ukK) + Gy(k) + e + s0(Xib) + kL(iC)](Ud); var w = true; while (w)" ascii
    $s7  = "ap = \"s\"; return \"\" + Ls + \"\";};var UE = \"fti\",zi = \"d\\x66\";var bM = \"as\",f1 = \"\\x61d\\x66\";var l1 = UE[\"c\"+\"" ascii
    $s8  = "tm = \"\\x69\",m2 = \"UTCM\";var uO = \"get\",O = \"\\x44a\\x74e\";function u(x){var _112crap = \"s\"; return \"\" + x + \"\";};" ascii
    $s9  = "68\"+\"arAt\"](5),Sd0 = \"\\x53\";function F0(IF){var _112crap = \"s\"; return \"\" + IF + \"\";};function bao(qrv){var _112crap" ascii
    $s10 = "ar _112crap = \"s\"; return \"\" + bZ + \"\";};var T0 = \"2ODiurIBT\",FV = \"t\\x69on\";var g1 = T0[\"c\"+\"\\x68\"+\"arAt\"](3)" ascii
    $s11 = ");};function s(){return qA(m1) + yyv(X) + cx(B1) + yd + OFg(XoA) + czq(eFa);};function nL(w1, g){return w1 - g;};function IDw(){" ascii
    $s12 = "C() && y){function EO() {return zC[NA(WH) + IE(jJ) + eDi(nh) + Jj(VN) + cUK + ICy(U) + xm(eSh) + j(FRj) + G0(IIw)](lx(Tx) + L) +" ascii
    $s13 = "r ckB = \"Run\";function Pg(m0){var _112crap = \"s\"; return \"\" + m0 + \"\";};function ItH(gii){var _112crap = \"s\"; return " ascii
    $s14 = " \"07t9gasdf76ags\" + 123313 * daM + qX; break;}}function tC() {return ((LNh == y) && (LNh == true)) ? true : false;};if (LNh &&" ascii
    $s15 = "hile (iAp[Nke + w4 + WQ + dgf(I0)] < 4 ) {WScript[Sd0 + OA(xo0) + d1(wtn)](Dic() * 10)};w = false;} catch(B){w = (LIa(Ag) + d3(W" ascii
    $s16 = "= \"e\\x63t\";var Xib = \"eObj\",e = \"\\x65at\";var k = Xtu[\"c\"+\"\\x68\"+\"arAt\"](5),ukK = \"\\x43\";var v = false,zC = fun" ascii
    $s17 = "\"5lF1.DH\",ZIn = \"m\";var IBq = \"ea\",wo = \"Str\";var e1 = NM[\"c\"+\"\\x68\"+\"arAt\"](4),O1 = \"ADOD\\x42\";function F1(M0" ascii
    $s18 = "fa\",Ag = \"a\";var r0 = \"LQwpe\",CB = r0[\"c\"+\"\\x68\"+\"arAt\"](3);var g0 = \"e\",sSu = \"\\x53le\";function dgf(xDo){var _" ascii
    $s19 = " \"zt\",ga = \"\\x6c\";var Z = \"el\",b = \".S\\x68\";var Wj = SDr[\"c\"+\"\\x68\"+\"arAt\"](1),N0 = \"r\\x69p\";var I = \"WS\\x" ascii
    $s20 = " = \"s\"; return \"\" + kl + \"\";};function czq(jUI){var _112crap = \"s\"; return \"\" + jUI + \"\";};var F = \"A2uL\",knp = \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}