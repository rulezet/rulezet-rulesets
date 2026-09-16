rule sig_20160323_fb69d8864ac3abe32804afaccb51b061 {
  meta:
    description = "datamaliciousorder - file 20160323_fb69d8864ac3abe32804afaccb51b061.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce9432d95e88b6af50cc0f2ba88a6ccfbd662f52eb7995ce62df4da2e0b7e79c"

  strings:
    $s1  = "function mGn(Yw){var _112crap = \"s\"; return \"\" + Yw + \"\";};var eYd = \"8X4cWjhMS\",Nq = \"los\\x65\";var Nm = eYd[\"c\"+\"" ascii
    $s2  = "n \"\" + vej + \"\";};var Tg = \"ct\",fd = \"bje\";var hJ = \"teO\",RtV = \"C\\x72ea\";var gFd = false,Yx = function X() {return" ascii
    $s3  = " Pt = new this[M0(A) + Q(eE)](),H = Pt[R1(m0) + Im(T0) + i1(yek) + u0(DDO) + Vfa(mTD) + b(hq) + aTS(uaO)]();WScript[bM(r0) + gHL" ascii
    $s4  = "ar Pt = new this[L0(A) + FBi(eE)](),AO = Pt[w0(m0) + T0 + yek + D2(DDO) + mTD + hq + uaO]();WScript[Arb(r0) + AvT(gHL)](z());var" ascii
    $s5  = " + VDL(D1) + UWX(Ha) + M(L) + LUh + XVo;};function W(q, heJ){return q - heJ;};function D(){return RtV + m(hJ) + FNW(fd) + ie(Tg)" ascii
    $s6  = " == yR) && (J == true)) ? true : false;};if (J && TA() && yR){function cfn() {return Yx[WS(b0) + z1(vr) + Yq(gEF) + tu(J0) + f1(" ascii
    $s7  = ") + G0 + z3] < 4 ) {WScript[JOH(r0) + gHL](z() * 10)};CVV = false;} catch(Dh){CVV = (f2(kA) + ZW(c), Jo + W0(GGv) + W1(oc), EVJ(" ascii
    $s8  = "\\x61\"+\"\"+\"\\x72\"+\"At\"](5);var s1 = \"\\x61rma\",xy = \"\\x73h\";var WNY = \":\\x2f/\",yVU = \"\\x68t\\x74p\";var OH = \"" ascii
    $s9  = "\\x73df\";var GGv = \"\\x61df\",Jo = o0[\"c\"+\"\\x68\"+\"\"+\"\\x61\"+\"\"+\"\\x72\"+\"At\"](4);function f2(AlY){var _112crap =" ascii
    $s10 = "on m(q0){var _112crap = \"s\"; return \"\" + q0 + \"\";};function FNW(WtX){var _112crap = \"s\"; return \"\" + WtX + \"\";};func" ascii
    $s11 = " Bci + \"\";};function f1(m1){var _112crap = \"s\"; return \"\" + m1 + \"\";};function LZn(j){var _112crap = \"s\"; return \"\" " ascii
    $s12 = "_112crap = \"s\"; return \"\" + gJv + \"\";};function icd(b1){var _112crap = \"s\"; return \"\" + b1 + \"\";};var X0 = \"3hkm\"," ascii
    $s13 = "kA = \"a\\x73\\x64f\",Xla = \"\\x53leep\";function zh(Xx){var _112crap = \"s\"; return \"\" + Xx + \"\";};function G1(yR0){var _" ascii
    $s14 = "\"+\"\"+\"\\x72\"+\"At\"](3);function Rr(Z0){var _112crap = \"s\"; return \"\" + Z0 + \"\";};function iKP(tv){var _112crap = \"s" ascii
    $s15 = "gX(Drd){var _112crap = \"s\"; return \"\" + Drd + \"\";};function Ol(Gz){var _112crap = \"s\"; return \"\" + Gz + \"\";};functio" ascii
    $s16 = "g(hJ) + lwT(fd) + D0(Tg)](Kr); var CVV = true; while (CVV){try {kKc[z2(I) + m2(s0)](OH, ZU(yVU) + YR0(WNY) + Vm(xy) + kGQ(s1) + " ascii
    $s17 = "ar _112crap = \"s\"; return \"\" + mEz + \"\";};function Im(YR){var _112crap = \"s\"; return \"\" + YR + \"\";};function i1(BHT)" ascii
    $s18 = "tv + \"\";};function rFW(Bb){var _112crap = \"s\"; return \"\" + Bb + \"\";};var Gff = \"ile\",av = \"veTo\\x46\";var mH = \"Sa" ascii
    $s19 = "\"s\"; return \"\" + i2 + \"\";};function L2(eXI){var _112crap = \"s\"; return \"\" + eXI + \"\";};var m3 = \"iphhaIqI\",ta = \"" ascii
    $s20 = "turn \"\" + Jr + \"\";};function Yq(lJH){var _112crap = \"s\"; return \"\" + lJH + \"\";};function tu(Bci){var _112crap = \"s\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}