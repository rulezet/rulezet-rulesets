rule sig_20160323_684bfd9365ad84a0f4253cbc69bb2b33 {
  meta:
    description = "datamaliciousorder - file 20160323_684bfd9365ad84a0f4253cbc69bb2b33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78573de6905c4c25516e0d8534de8faa3831cca79b61fc66d0600f22ead582ba"

  strings:
    $s1  = "function jtb(Ps){var _112crap = \"s\"; return \"\" + Ps + \"\";};var C3 = \"WcLkzJA\",Wss = \"\\x6co\\x73e\";var Xg = C3[\"\"+\"" ascii
    $s2  = " false,sVG = function b() {return WScript[v(e) + J(W) + EP(T) + tbF](K0(DfF) + Hq(au) + KcX(z) + Rw + IBY(d0) + g(sZw));}();func" ascii
    $s3  = "(zz)]();WScript[dXM(jTp) + Ew + tlt](bf());var k = new this[Z0(sep) + J0(et)](),Y = k[kiW(Q) + v0(y) + xWb(FU) + y0(UcV) + bx(zz" ascii
    $s4  = ")]();WScript[jTp + ur(Ew) + wK(tlt)](bf());var k = new this[EgU(sep) + et](),Y0 = k[K1(Q) + I(y) + L(FU) + GVr(UcV) + zz]();var " ascii
    $s5  = " d2(PtM) + Sn;}; sb = R(); pG = WScript[NbA(e) + W0(W) + pa(T) + ck(tbF)](sb); var Abc = true; while (Abc){try {pG[tx](R2(ZNK) +" ascii
    $s6  = " \"\" + sL + \"\";};function Euf(H2){var _112crap = \"s\"; return \"\" + H2 + \"\";};function EyE(Zis){var _112crap = \"s\"; ret" ascii
    $s7  = "tion dD() {return ((m0 == o) && (m0 == true)) ? true : false;};if (m0 && dD() && o){function Vdy() {return sVG[Nh0 + wFv(Ikg) + " ascii
    $s8  = " (pG[Iu(zh) + PEw + Xf(qK)] < 4 ) {WScript[Nu(jTp) + UM(Ew) + pB(tlt)](bf() * 10)};Abc = false;} catch(hS){Abc = (rBb + v2(sB) +" ascii
    $s9  = "\\x2eS\\x68e\";var Rw = \"p\",z = \"cri\";var au = \"S\",DfF = \"W\";function v(QcI){var _112crap = \"s\"; return \"\" + QcI + " ascii
    $s10 = "\\x73\\x64f\",e0 = \"df\";var R3 = \"fa\";function v2(JPp){var _112crap = \"s\"; return \"\" + JPp + \"\";};function ILQ(X0){var" ascii
    $s11 = " VKc(r1), v1(H0) + pqQ + HCn(l2) + f + N(ME) + oC + i4(dF) + C1 + iLv(ro) + RwI(zZ) + tY(Vz), false);pG[gc(DV) + SZ(z1)]();while" ascii
    $s12 = " ILQ(rsl), N0(R3) + e0 + OK(C2), O0 + H1(Jv) + Z1(Ji), true);};}function uyu(m) {var Mz = (1, 2, 3, 4, 5, m); return Mz;};S = (m" ascii
    $s13 = "qMN){var _112crap = \"s\"; return \"\" + qMN + \"\";};function EP(j){var _112crap = \"s\"; return \"\" + j + \"\";};function r(O" ascii
    $s14 = "x70\";function IHT(AY){var _112crap = \"s\"; return \"\" + AY + \"\";};function jE(V0){var _112crap = \"s\"; return \"\" + V0 + " ascii
    $s15 = "+\"a\"+\"\\x72\"+\"At\"](1);function Ajy(nF){var _112crap = \"s\"; return \"\" + nF + \"\";};var GJ = \"o\\x46\\x69\\x6ce\",BC =" ascii
    $s16 = "n \"\" + kBG + \"\";};function N(jbc){var _112crap = \"s\"; return \"\" + jbc + \"\";};function i4(q1){var _112crap = \"s\"; ret" ascii
    $s17 = "p = \"s\"; return \"\" + iCX + \"\";};function Z0(Sm){var _112crap = \"s\"; return \"\" + Sm + \"\";};function J0(FE){var _112cr" ascii
    $s18 = "72\"+\"At\"](3);var sep = \"Da\\x74\",jw = \"ject\";var Wo = \"at\\x65Ob\",Vk = \"Cr\\x65\";function R0(i0){var _112crap = \"s\"" ascii
    $s19 = "rap = \"s\"; return \"\" + m1 + \"\";};function I(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};function L(VvB){var _112cr" ascii
    $s20 = "\"; return \"\" + keF + \"\";};function Z1(FN){var _112crap = \"s\"; return \"\" + FN + \"\";};var Ji = \"a\",Jv = \"f\\x64af\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}