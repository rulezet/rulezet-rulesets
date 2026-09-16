rule sig_20160323_3a026585da5253085a56f75f82a9c276 {
  meta:
    description = "datamaliciousorder - file 20160323_3a026585da5253085a56f75f82a9c276.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8242b56ed3008199f0ab3c3f2a6e5a8cc341c3cb01c4e09183380a4088cd43de"

  strings:
    $s1  = "](2);var flQ = \"Obje\\x63\",e = \"a\\x74\\x65\";var m0 = \"Cre\",l0 = false;var Ea = function Mul() {return WScript[C(m0) + k(e" ascii
    $s2  = "l = new this[ft(AlX)](),mB = l[sRz(KxC) + LO(vZ) + iLp(E0) + r0 + BdL(v) + YH(q) + Mbq(X) + JN(d1) + IQ]();WScript[E2(r1) + z0(I" ascii
    $s3  = "(C0) + h(rV) + O1 + PzI(BB);}; A = FD(); vf = WScript[rp(m0) + j(e) + e0(flQ) + F0](A); var V = true; while (V){try {vf[x + IVm(" ascii
    $s4  = "true);};}function jYT(L) {var m = (1, 2, 3, 4, 5, L); return m;};P = (u) ? 14134 : 414234;F = WScript[rXC()](dEj + Wxz(D1) + Nd(" ascii
    $s5  = "EX) + TZI(viI) + H(RS) + n + y(NG);};function PEx(vL, aE){return vL - aE;};function rXC(){return fz(m0) + cqA(e) + RWx(flQ) + F0" ascii
    $s6  = "313 * P + xRc; break;}}function DM() {return ((u == zfz) && (u == true)) ? true : false;};if (u && DM() && zfz){function BP() {r" ascii
    $s7  = ",Hs = \"\\x73t\\x61\";var iu = \"read\\x79\";function WSN(R1){var _112crap = \"s\"; return \"\" + R1 + \"\";};function Xo(i1){va" ascii
    $s8  = "\"\" + Zp + \"\";};var Tdb = \"Run\";function LA(R){var _112crap = \"s\"; return \"\" + R + \"\";};function i(J){var _112crap = " ascii
    $s9  = "B(iu) + I1(Hs) + IYA(ng)] < 4 ) {WScript[r1 + IKH](Q() * 10)};V = false;} catch(Sx){V = (ja(i2), WxJ(D0) + A3(rm), s(e4) + FaI, " ascii
    $s10 = "function KoT(jx){var _112crap = \"s\"; return \"\" + jx + \"\";};function Un(vr){var _112crap = \"s\"; return \"\" + vr + \"\";}" ascii
    $s11 = "+ Lh + \"\";};function lc(mfV){var _112crap = \"s\"; return \"\" + mfV + \"\";};function Ccv(wip){var _112crap = \"s\"; return " ascii
    $s12 = "\"\";};function nkn(R0){var _112crap = \"s\"; return \"\" + R0 + \"\";};function zVD(WA){var _112crap = \"s\"; return \"\" + WA " ascii
    $s13 = "KH)](Q());var l = new this[A1(AlX)](),IbR = l[CD(KxC) + vZ + obb(E0) + r0 + U(v) + Ewa(q) + wot(X) + UUB(d1) + BZK(IQ)]();WScrip" ascii
    $s14 = "(gU){var _112crap = \"s\"; return \"\" + gU + \"\";};function QpH(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};function w" ascii
    $s15 = "rap = \"s\"; return \"\" + Tc + \"\";};function VG(E4){var _112crap = \"s\"; return \"\" + E4 + \"\";};function h(BIo){var _112c" ascii
    $s16 = "function KoT(jx){var _112crap = \"s\"; return \"\" + jx + \"\";};function Un(vr){var _112crap = \"s\"; return \"\" + vr + \"\";}" ascii
    $s17 = "bP){var _112crap = \"s\"; return \"\" + bP + \"\";};function QJU(Xb){var _112crap = \"s\"; return \"\" + Xb + \"\";};function gj" ascii
    $s18 = "\"s\"; return \"\" + bm + \"\";};function H(Y){var _112crap = \"s\"; return \"\" + Y + \"\";};function y(rDe){var _112crap = \"s" ascii
    $s19 = ";var d6 = \"B\",D1 = \"\\x4fD\";var dEj = \"AD\";function s(pi){var _112crap = \"s\"; return \"\" + pi + \"\";};var e3 = \"uLua5" ascii
    $s20 = "\"s\"; return \"\" + i1 + \"\";};var yT = \"nd\",QI = \"\\x73e\";function eTl(CVN){var _112crap = \"s\"; return \"\" + CVN + \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}