rule sig_20160323_221a6a183850b69e5b9539b9aec9072b {
  meta:
    description = "datamaliciousorder - file 20160323_221a6a183850b69e5b9539b9aec9072b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a4f1fe4592ec1a816ce40ab5be047e1cc8edf61dfa11b1496aaf8140dae7188"

  strings:
    $s1  = "function jl(yh){var _112crap = \"s\"; return \"\" + yh + \"\";};var zWc = \"EpHL3cc3\",Zbj = \"l\\x6fse\";var O1 = zWc[\"charA\"" ascii
    $s2  = ") + Ge](qJ());var aH = new this[bb](),Xb = aH[shv + nfD(cbC) + IcQ(Xm) + m(Uh) + fV]();WScript[i(dVY) + Ge](qJ());var aH = new t" ascii
    $s3  = "lPb[Ofo(a0) + RH(AkB)]();while (lPb[Jz(fO) + j0(vI) + U0(LYL) + Z0(g1)] < 4 ) {WScript[x(dVY) + Cxg(Ge)](qJ() * 10)};yJ = false;" ascii
    $s4  = "WScript[dpd(bEy) + WY + g + QeV(LKZ) + r0(c1) + gwb(WiO) + f0(tS)](c0); var yJ = true; while (yJ){try {lPb[NEM + BRj](M3(L0) + l" ascii
    $s5  = "22;};var RG = 0,vB = 0;function OP(){var aH = new this[wHE(bb)](),c = aH[shv + CNp(cbC) + Xm + ow(Uh) + A(fV)]();WScript[RAM(dVY" ascii
    $s6  = " 2, 3, 4, 5, TX); return sM;};RG = (uZi) ? 14134 : 414234;qoi = WScript[OTR()](i0(zdD) + zfR + K5(CN) + sHX(kp) + Nm(yr));c0 = q" ascii
    $s7  = "on lf(){return w(Vx) + apU(C) + HEc + e0(TrK) + Bm(qz);};function hGe(K, CjU){return K - CjU;};function OTR(){return Gw(bEy) + r" ascii
    $s8  = "gs\" + 123313 * RG + vB; B = true; vB = \"07t9gasdf76ags\" + 123313 * RG + vB; break;}}function Vn() {return ((uZi == B) && (uZi" ascii
    $s9  = " true)) ? true : false;};if (uZi && Vn() && B){function s() {return jxg[TV + u0(m0) + jlY(Um) + r2(YRA) + V1(Go) + DkW(FO) + It(" ascii
    $s10 = " \"s\"; return \"\" + fB + \"\";};function DkW(Cop){var _112crap = \"s\"; return \"\" + Cop + \"\";};function It(taB){var _112cr" ascii
    $s11 = "+\"\"](0);var LKZ = \"\\x62j\",g = \"\\x65a\\x74eO\";var WY = \"r\",bEy = \"\\x43\";var dM = false,jxg = function jG() {return W" ascii
    $s12 = "\\x64\";var MmE = \"po\\x6e\\x73\",i1 = \"\\x65s\";var K6 = t2[\"charA\"+\"\\x74\"+\"\"](4);function mj(KFQ){var _112crap = \"s" ascii
    $s13 = "li\\x73\\x65\";var Gx = \"CMi\\x6c\",Ikc = \"\\x54\";var swr = \"U\",AU = \"get\";var wtL = \"t\\x65\",X0 = \"Da\";function RAM(" ascii
    $s14 = "ar G1 = \"a\\x74e\",Y = \"Cre\";function Icp(j){var _112crap = \"s\"; return \"\" + j + \"\";};function T(b0){var _112crap = \"s" ascii
    $s15 = "(wQW){var _112crap = \"s\"; return \"\" + wQW + \"\";};var m1 = \"\\x73df\",l1 = \"fadfa\";function EbJ(rd){var _112crap = \"s\"" ascii
    $s16 = " \"\";};function RH(GF){var _112crap = \"s\"; return \"\" + GF + \"\";};var AkB = \"e\\x6ed\",a0 = \"s\";function PHD(peB){var _" ascii
    $s17 = " = \"se\";var Xm = \"\\x69lli\",cbC = \"tU\\x54CM\";var shv = \"ge\";function wHE(byF){var _112crap = \"s\"; return \"\" + byF +" ascii
    $s18 = "= \"C\\x72e\";function w(Hv){var _112crap = \"s\"; return \"\" + Hv + \"\";};function apU(GPV){var _112crap = \"s\"; return \"\"" ascii
    $s19 = " J(w0){var _112crap = \"s\"; return \"\" + w0 + \"\";};var bb = \"\\x44\\x61te\",VY = \"ct\";var r1 = \"je\",s1 = \"O\\x62\";var" ascii
    $s20 = " + \"\";};function vDA(g0){var _112crap = \"s\"; return \"\" + g0 + \"\";};var EQ = \"nr4CBb\",D = \"KiI\";var gm = \"\\x73\",cr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}