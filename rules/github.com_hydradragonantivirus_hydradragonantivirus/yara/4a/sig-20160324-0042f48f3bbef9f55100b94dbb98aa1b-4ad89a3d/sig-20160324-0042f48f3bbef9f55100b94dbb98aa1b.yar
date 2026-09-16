rule sig_20160324_0042f48f3bbef9f55100b94dbb98aa1b {
  meta:
    description = "datamaliciousorder - file 20160324_0042f48f3bbef9f55100b94dbb98aa1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c1f0789c7c6bf46e0ceaf4d27b5334971d93052f4ca2e0a231d0af4e88ca668"

  strings:
    $s1  = "+ Qa(vqC) + v0(dF), false);kUU[EYq]();while (kUU[B2(Eh) + hK(TwE) + QnR(hiA) + OH] < 4 ) {WScript[pYZ + nyw(EI) + IGw(xts)](IG()" ascii
    $s2  = "= \"Creat\";var sg = false,Ii = function ob() {return WScript[tk(rYJ) + sLI(KhQ) + d + qGi(NbF)](BU(d0) + w(ZS) + lkE(eL) + No(L" ascii
    $s3  = "w1) + aa(cu) + fdp + BGI + yBJ(CpO) + tB + z;}; GeQ = m(); kUU = WScript[kdg(rYJ) + Fu(KhQ) + d + NbF](GeQ); var p = true; while" ascii
    $s4  = "ag); return I;};PB = (j) ? 14134 : 414234;KFF = WScript[xB()](L0(dGA) + j1(sY) + x1(dCK) + ss(TSM));GeQ = KFF;B = (lt) ? PB : B;" ascii
    $s5  = "function qwF(HXR){var _112crap = \"s\"; return \"\" + HXR + \"\";};var Ra = \"se\",l = \"clo\";function UVo(DM){var _112crap = " ascii
    $s6  = "e; B = \"07t9gasdf76ags\" + 123313 * PB + B; break;}}function EJ() {return ((j == lt) && (j == true)) ? true : false;};if (j && " ascii
    $s7  = "() && lt){function Q() {return Ii[yiU(ULg) + HEK + b(Ml) + do0(A0) + j0(Dih) + AR(C0) + V2(Rn)](H2(Sn) + uv(pnT)) + bKL(p1) + f(" ascii
    $s8  = "ap = \"s\"; return \"\" + rl + \"\";};function ss(s1){var _112crap = \"s\"; return \"\" + s1 + \"\";};var Uq = \"telPg.LOc\",TSM" ascii
    $s9  = "\" + ScR + \"\";};function UDc(H1){var _112crap = \"s\"; return \"\" + H1 + \"\";};function g0(LLC){var _112crap = \"s\"; return" ascii
    $s10 = "\\x53XM\";function M(lcx){var _112crap = \"s\"; return \"\" + lcx + \"\";};var Fr = \"R\\x75n\";function BU(O){var _112crap = \"" ascii
    $s11 = "0 = \"\\x70\\x6fsi\";function jVt(S2){var _112crap = \"s\"; return \"\" + S2 + \"\";};function vg(z0){var _112crap = \"s\"; retu" ascii
    $s12 = "n \"\" + AOG + \"\";};function Fu(FtX){var _112crap = \"s\"; return \"\" + FtX + \"\";};var NbF = \"\\x6a\\x65ct\",d = \"b\";var" ascii
    $s13 = "n bKL(LZN){var _112crap = \"s\"; return \"\" + LZN + \"\";};function f(cX){var _112crap = \"s\"; return \"\" + cX + \"\";};funct" ascii
    $s14 = "tion G0(gp){var _112crap = \"s\"; return \"\" + gp + \"\";};var RyT = \"sdfa\",Iks = \"a\";var Rv = \"ep\",xNJ = \"Sle\";functio" ascii
    $s15 = "YC){var _112crap = \"s\"; return \"\" + EYC + \"\";};function fs(O0){var _112crap = \"s\"; return \"\" + O0 + \"\";};function h(" ascii
    $s16 = " NL(WR){var _112crap = \"s\"; return \"\" + WR + \"\";};function K0(eSN){var _112crap = \"s\"; return \"\" + eSN + \"\";};functi" ascii
    $s17 = " = \"s\"; return \"\" + C + \"\";};function vU(Da){var _112crap = \"s\"; return \"\" + Da + \"\";};function JWK(rLA){var _112cra" ascii
    $s18 = "var _112crap = \"s\"; return \"\" + X0 + \"\";};function j1(GfJ){var _112crap = \"s\"; return \"\" + GfJ + \"\";};function x1(rl" ascii
    $s19 = ",AIA = \"eObj\";var XD = \"ea\\x74\",xo = \"Cr\";function ho(rHR){var _112crap = \"s\"; return \"\" + rHR + \"\";};function S(C)" ascii
    $s20 = "LZe){var _112crap = \"s\"; return \"\" + LZe + \"\";};function ixZ(a0){var _112crap = \"s\"; return \"\" + a0 + \"\";};function " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}