rule sig_20160323_ce6f7778e9f9407e7944d15fb29f64e2 {
  meta:
    description = "datamaliciousorder - file 20160323_ce6f7778e9f9407e7944d15fb29f64e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a266d34bfa65aa4d447e68ab0572478f7759cb19eb1e5b9b6f3209db3aaeda97"

  strings:
    $s1  = "() {return WScript[W + F + ma(dV) + fIA + hY + AR(Qa)](O0 + Xv0(kG) + MJg(It) + ud(MyU) + C(JbV));}();function Bv(P){kr[q(w)](P," ascii
    $s2  = "AG = GuE(); qp = WScript[r0(W) + eW(F) + dV + fIA + S(hY) + A0(Qa)](AG); var wB = true; while (wB){try {qp[xXK + h0(a)](bVc(zwO)" ascii
    $s3  = "(G0) + ih(KK)]();WScript[nSP(c)](Gk());var BtR = new this[UY(vch) + T(uWM)](),YSX = BtR[Ex(VdN) + JM(Xi) + GT(G) + l(G0) + XG(KK" ascii
    $s4  = "var Yy = \"cl\\x6fse\";function XNF(hk){var _112crap = \"s\"; return \"\" + hk + \"\";};function CPe(r2){var _112crap = \"s\"; r" ascii
    $s5  = "J) + XxD, true);};}function tu(Dl) {var QiG = (1, 2, 3, 4, 5, Dl); return QiG;};BGo = (ht) ? 14134 : 414234;BE = WScript[Fnh()](" ascii
    $s6  = ")]();WScript[Jcp(c)](Gk());var BtR = new this[s(vch) + rJ(uWM)](),vPv = BtR[Br(VdN) + Xi + P1(G) + G0 + pWe(KK)]();var BGo = \"f" ascii
    $s7  = " 0, 0);};function GuE(){return gST + A1 + wZf + L0 + m(o) + Bc + t;};function dhh(r, AQf){return r - AQf;};function Fnh(){return" ascii
    $s8  = "* 1; YA++){if (D() != 0){ht = true; PS = \"07t9gasdf76ags\" + 123313 * BGo + PS; jW = true; PS = \"07t9gasdf76ags\" + 123313 * B" ascii
    $s9  = " w = \"Run\";function Xv0(Cx){var _112crap = \"s\"; return \"\" + Cx + \"\";};function MJg(sZ){var _112crap = \"s\"; return \"\"" ascii
    $s10 = "();while (qp[aG + o1(Q0) + qG(RyQ)] < 4 ) {WScript[c](Gk() * 10)};wB = false;} catch(wD){wB = (IL, V1(S2) + Qg + Hha(W1), iba(vC" ascii
    $s11 = "ction hW(Is){var _112crap = \"s\"; return \"\" + Is + \"\";};function ij(p){var _112crap = \"s\"; return \"\" + p + \"\";};funct" ascii
    $s12 = "112crap = \"s\"; return \"\" + uLT + \"\";};var a = \"e\\x6e\",xXK = \"op\";var dLp = \"t\",po = \"Zpjpentd7\";var ZN = \"ct\",d" ascii
    $s13 = "\" + d + \"\";};function Ex(Yvf){var _112crap = \"s\"; return \"\" + Yvf + \"\";};function JM(wfX){var _112crap = \"s\"; return " ascii
    $s14 = "= \"s\"; return \"\" + kPh + \"\";};var OQ = \"HTGLe\",uWM = OQ[\"cha\"+\"\\x72\"+\"At\"](4);var vch = \"D\\x61\\x74\",kqo = \"e" ascii
    $s15 = "_112crap = \"s\"; return \"\" + ZxR + \"\";};function s(vF0){var _112crap = \"s\"; return \"\" + vF0 + \"\";};function rJ(kPh){v" ascii
    $s16 = ";};var b0 = \"xe\",Wx = \"mS.e\";var WDn = \"\\x4flii\\x56\",hTk = \"3\\x4b\\x67\";function B(dn){var _112crap = \"s\"; return " ascii
    $s17 = " o = \"XM\",L0 = \".\";var wZf = \"\\x4c2\",A1 = \"S\\x58\\x4d\";var gST = \"M\";function q(kQ){var _112crap = \"s\"; return \"" ascii
    $s18 = "G(u){var _112crap = \"s\"; return \"\" + u + \"\";};function Br(ddx){var _112crap = \"s\"; return \"\" + ddx + \"\";};function P" ascii
    $s19 = "112crap = \"s\"; return \"\" + z + \"\";};function ie(z0){var _112crap = \"s\"; return \"\" + z0 + \"\";};function HvK(oH){var _" ascii
    $s20 = "\"\";};function GT(Q){var _112crap = \"s\"; return \"\" + Q + \"\";};function l(tR){var _112crap = \"s\"; return \"\" + tR + \"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}