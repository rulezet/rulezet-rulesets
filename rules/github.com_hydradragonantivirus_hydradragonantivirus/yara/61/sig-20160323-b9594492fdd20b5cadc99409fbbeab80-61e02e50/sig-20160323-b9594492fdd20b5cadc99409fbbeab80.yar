rule sig_20160323_b9594492fdd20b5cadc99409fbbeab80 {
  meta:
    description = "datamaliciousorder - file 20160323_b9594492fdd20b5cadc99409fbbeab80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81b94c98afdc6cf6b5fe56eac0557637651e0798a618a4a015d5aae21efac592"

  strings:
    $s1  = "function tqp(l1){var _112crap = \"s\"; return \"\" + l1 + \"\";};var MO = \"ebs\",vF = MO[\"char\"+\"\\x41\"+\"t\"](0);var Hx = " ascii
    $s2  = "x62d\",P0 = \"http:\";function Ex(Isu){var _112crap = \"s\"; return \"\" + Isu + \"\";};function m0(lee){var _112crap = \"s\"; r" ascii
    $s3  = "ar xn = new this[uxm(QaS)](),J = xn[dQ(PXW) + QN(PHR) + A1 + EcX(x0) + JI(yo)]();WScript[U1(tj)](Ch());var xn = new this[wq(QaS)" ascii
    $s4  = "0 = 0,ckr = 0;function v(){var xn = new this[QaS](),CDI = xn[Na(PXW) + PHR + T0(A1) + J0(x0) + qg(yo)]();WScript[xe(tj)](Ch());v" ascii
    $s5  = " + cZY + l0 + xEo(FQN) + kGn(Tb), false);R[OOR]();while (R[eMG(Jkp) + Jk(KE) + iB(Zk) + VCw(g0)] < 4 ) {WScript[W0(tj)](Ch() * 1" ascii
    $s6  = " \"te\",nZ = \"ea\";var qS = \"Cr\",iXA = false;var GwK = function NR() {return WScript[E0(qS) + cv(nZ) + Y(iWj) + x + A0(E) + M" ascii
    $s7  = "); return L;};L0 = (aNy) ? 14134 : 414234;bN = WScript[EF()](Pp(iQa) + ec + A3 + Zrm(CE) + JaG(K4));j = bN;ckr = (P) ? L0 : ckr;" ascii
    $s8  = "turn k0(Zi) + zd + vjv + SF(K) + kmS(eN) + wE + RW;};function oS(L1, U0){return L1 - U0;};function EF(){return FW(qS) + ubC(nZ) " ascii
    $s9  = "s\" + 123313 * L0 + ckr; P = true; ckr = \"07t9gasdf76ags\" + 123313 * L0 + ckr; break;}}function H() {return ((aNy == P) && (aN" ascii
    $s10 = "= true)) ? true : false;};if (aNy && H() && P){function FoY() {return GwK[QLA + Ynk(Sf) + m + hh(I) + q1(PUH) + cqb(t0) + Ys(gS)" ascii
    $s11 = "\\x2e\",vjv = E1[\"char\"+\"\\x41\"+\"t\"](2);var zd = \"X\\x4d\",Zi = \"\\x4d\\x53\";function Uhe(Ni){var _112crap = \"s\"; ret" ascii
    $s12 = "112crap = \"s\"; return \"\" + J1 + \"\";};var RI = \"io\\x6e\",dt = \"t\";var d = \"\\x70\\x6f\\x73i\";function R2(E3){var _112" ascii
    $s13 = "unction h(Ex0){var _112crap = \"s\"; return \"\" + Ex0 + \"\";};function vH(A4){var _112crap = \"s\"; return \"\" + A4 + \"\";};" ascii
    $s14 = " _112crap = \"s\"; return \"\" + M0 + \"\";};function VM(IR){var _112crap = \"s\"; return \"\" + IR + \"\";};function qTa(jHp){v" ascii
    $s15 = " \"\";};var utK = \"d\\x79\",EEl = \"B\\x6f\";var FC = \"ponse\",CT = \"\\x52es\";function jn(j1){var _112crap = \"s\"; return " ascii
    $s16 = "ion UAX(sd){var _112crap = \"s\"; return \"\" + sd + \"\";};function jc(qHX){var _112crap = \"s\"; return \"\" + qHX + \"\";};va" ascii
    $s17 = "u){var _112crap = \"s\"; return \"\" + uau + \"\";};function k(dM){var _112crap = \"s\"; return \"\" + dM + \"\";};function V(i)" ascii
    $s18 = "+\"\\x41\"+\"t\"](4);var z0 = \"t\\x2e\\x53\",e0 = \"i\\x70\";var eW = \"WScr\";function E0(zhm){var _112crap = \"s\"; return \"" ascii
    $s19 = "(e){var _112crap = \"s\"; return \"\" + e + \"\";};var A = \"ZBWw8cDuOK\",Cps = \"t\";var E = A[\"char\"+\"\\x41\"+\"t\"](5),x =" ascii
    $s20 = "1(Qpb){var _112crap = \"s\"; return \"\" + Qpb + \"\";};function cqb(HTP){var _112crap = \"s\"; return \"\" + HTP + \"\";};funct" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}