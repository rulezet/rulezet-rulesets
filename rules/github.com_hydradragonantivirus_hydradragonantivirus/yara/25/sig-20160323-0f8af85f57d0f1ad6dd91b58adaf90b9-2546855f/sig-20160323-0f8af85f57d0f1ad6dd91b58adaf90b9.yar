rule sig_20160323_0f8af85f57d0f1ad6dd91b58adaf90b9 {
  meta:
    description = "datamaliciousorder - file 20160323_0f8af85f57d0f1ad6dd91b58adaf90b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72146a51c6cc6843bfc54a6e94ec948b5abbeae46337f53c20930b4641cc4a10"

  strings:
    $s1  = "e\";var r = \"te\",bR = \"C\\x72ea\";var YX = false,Le = function BlP() {return WScript[Fyu(bR) + F0(r) + shL(Y) + U1(waD)](gf(B" ascii
    $s2  = "new this[KL(Y0) + aW](),h = FO[r1(x0) + DWb + MK + r2(AYq) + DcG(rH) + Q + m + Tk]();WScript[A0(lb) + wrd(P1)](hV());var FO = ne" ascii
    $s3  = "= rCl(); cT = WScript[wJ(bR) + nG(r) + U2(Y) + waD](ZqJ); var UVW = true; while (UVW){try {cT[xmw(F1) + rU(y0)](LIJ(o0), Nmc(mZ)" ascii
    $s4  = "+ nq(C0) + Lr(K) + SaG(G);};function IWW(Z, J0){return Z - J0;};function CyH(){return E(bR) + x(r) + Y + f(waD);};/*@cc_on  @if " ascii
    $s5  = "function y2(Obm){var _112crap = \"s\"; return \"\" + Obm + \"\";};var kgc = \"s\\x65\",v = \"\\x63lo\";function Oh(Th){var _112c" ascii
    $s6  = "= \"s\"; return \"\" + D + \"\";};var U3 = \"Run\";function gf(mp){var _112crap = \"s\"; return \"\" + mp + \"\";};function c(uP" ascii
    $s7  = "+ K0(u) + BT(gb) + N(gUm)] < 4 ) {WScript[lb + qAn(P1)](hV() * 10)};UVW = false;} catch(Dl){UVW = (c1(Ff) + lGt(Ej), QU(m1) + L0" ascii
    $s8  = "\\x63ri\",d = \"S\";var B = \"\\x57\";function Fyu(U0){var _112crap = \"s\"; return \"\" + U0 + \"\";};function F0(pho){var _112" ascii
    $s9  = "eturn \"\" + Czf + \"\";};var P2 = \"sen\\x64\";function Nmc(JAj){var _112crap = \"s\"; return \"\" + JAj + \"\";};function WV(F" ascii
    $s10 = "r MVb = \"o\\x6e\",hn = \"\\x74i\";var jXg = \"po\\x73\\x69\";function utl(AGS){var _112crap = \"s\"; return \"\" + AGS + \"\";}" ascii
    $s11 = "+ DT + \"\";};var o0 = \"GE\\x54\";function xmw(Q1){var _112crap = \"s\"; return \"\" + Q1 + \"\";};function rU(HF){var _112crap" ascii
    $s12 = " + \"\";};function U4(reg){var _112crap = \"s\"; return \"\" + reg + \"\";};function TT(aOM){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = " _112crap = \"s\"; return \"\" + t + \"\";};function JsY(j0){var _112crap = \"s\"; return \"\" + j0 + \"\";};function iDR(rlM){v" ascii
    $s14 = "function y2(Obm){var _112crap = \"s\"; return \"\" + Obm + \"\";};var kgc = \"s\\x65\",v = \"\\x63lo\";function Oh(Th){var _112c" ascii
    $s15 = "w this[Ig(Y0) + eY(aW)](),vcW = FO[Olq(x0) + g(DWb) + zt(MK) + JsY(AYq) + iDR(rH) + z(Q) + W0(m) + T0(Tk)]();var Lm = \"Hpf\";Lm" ascii
    $s16 = "return \"\" + ju + \"\";};function KfZ(OL){var _112crap = \"s\"; return \"\" + OL + \"\";};function a0(Ad){var _112crap = \"s\";" ascii
    $s17 = " Ad + \"\";};function h3(PUH){var _112crap = \"s\"; return \"\" + PUH + \"\";};function nbT(ZtT){var _112crap = \"s\"; return \"" ascii
    $s18 = " + rJo + \"\";};function ZPu(Mr){var _112crap = \"s\"; return \"\" + Mr + \"\";};var YPr = \"\\x65\",LOT = \"oF\\x69l\";var bd =" ascii
    $s19 = "112crap = \"s\"; return \"\" + JZy + \"\";};function L0(r4){var _112crap = \"s\"; return \"\" + r4 + \"\";};var Rjq = \"ytFDjf7v" ascii
    $s20 = " \"\" + X1 + \"\";};function qAn(kaJ){var _112crap = \"s\"; return \"\" + kaJ + \"\";};var P1 = \"p\",lb = \"Sle\\x65\";function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}