rule sig_20160323_6a0f192148b26bf16944437224d241e6 {
  meta:
    description = "datamaliciousorder - file 20160323_6a0f192148b26bf16944437224d241e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaeb5617b94caf4521aea2e26423c6914da48eda026df6ccb1b3856f9e248886"

  strings:
    $s1  = "var ojE = \"ncJoW\",zP = \"los\\x65\";var giq = ojE[\"\"+\"\\x63\"+\"harA\"+\"\\x74\"+\"\"](1);function b3(H1){var _112crap = \"" ascii
    $s2  = " return \"\" + g0 + \"\";};var OnP = \"%/\",Iv = \"%TEMP\";function cU(Zmv){var _112crap = \"s\"; return \"\" + Zmv + \"\";};fun" ascii
    $s3  = "(),fHS = lU[sm + h0(L1) + iY(sm0) + t2(fZH) + qq(eC)]();WScript[K(Pfc) + re + A0(Vm)](G());var lU = new this[H(hUK)](),hl = lU[f" ascii
    $s4  = ")](),i = lU[cH(sm) + jw(L1) + T0(sm0) + cZ(fZH) + PaV(eC)]();WScript[B0(Pfc) + eRf(re) + Id(Vm)](G());var lU = new this[L0(hUK)]" ascii
    $s5  = "Yo(KM) + Xn, true);};}function gvZ(oL) {var FSC = (1, 2, 3, 4, 5, oL); return FSC;};Loz = (L) ? 14134 : 414234;Nc = WScript[Yxt(" ascii
    $s6  = " \"C\";var ciS = false,Mf = function MJz() {return WScript[fA(P) + a + aVI(cq) + Bd(HW) + xl + o(M0) + X0(T)](iN(rix) + e(Wn) + " ascii
    $s7  = "ap = \"s\"; return \"\" + sdB + \"\";};var SB = \"rfc7c\",Wr = \"Shell\";var B = \"ip\\x74.\",Wn = SB[\"\"+\"\\x63\"+\"harA\"+\"" ascii
    $s8  = "PEc){return bra - PEc;};function Yxt(){return sDP(P) + I(a) + fZ(cq) + HW + CGN(xl) + x0(M0) + XPw(T);};/*@cc_on  @if (@_win32 |" ascii
    $s9  = "? true : false;};if (L && M() && yZv){function HIY() {return Mf[cU(bpm) + M1(Ox) + vsi + r2 + IBZ + yX(YHL) + vJJ(Zb)](B1(Iv) + " ascii
    $s10 = " * Loz + QOw; yZv = true; QOw = \"07t9gasdf76ags\" + 123313 * Loz + QOw; break;}}function M() {return ((L == yZv) && (L == true)" ascii
    $s11 = "y(Hn)] < 4 ) {WScript[Pfc + QNE(re) + ACm(Vm)](G() * 10)};fWQ = false;} catch(R){fWQ = (Z2(B4), IAU(qzL) + Ur + RWA(pXe) + x3, y" ascii
    $s12 = " \"\";};function qq(l0){var _112crap = \"s\"; return \"\" + l0 + \"\";};function fY(ItP){var _112crap = \"s\"; return \"\" + ItP" ascii
    $s13 = "isec\";var sm0 = \"l\",L1 = \"C\\x4dil\";var sm = \"\\x67et\\x55T\";function gWJ(a0){var _112crap = \"s\"; return \"\" + a0 + \"" ascii
    $s14 = "var _112crap = \"s\"; return \"\" + JYD + \"\";};function yX(v){var _112crap = \"s\"; return \"\" + v + \"\";};function vJJ(b2){" ascii
    $s15 = "2 = \"ht\";function Oqw(Q0){var _112crap = \"s\"; return \"\" + Q0 + \"\";};function Z1(eVr){var _112crap = \"s\"; return \"\" +" ascii
    $s16 = "(xYH){var _112crap = \"s\"; return \"\" + xYH + \"\";};function H(r){var _112crap = \"s\"; return \"\" + r + \"\";};var hUK = \"" ascii
    $s17 = "{var _112crap = \"s\"; return \"\" + IGC + \"\";};var weK = \"en\",I0 = \"op\";var vn = \"CtB\",Lmc = \"e\";var KB = \"t\",QvP =" ascii
    $s18 = "9o\";var CXN = \"\\x70o\\x73\";function Tq(n0){var _112crap = \"s\"; return \"\" + n0 + \"\";};function Ly(uF){var _112crap = \"" ascii
    $s19 = " + U0 + \"\";};var Vm = \"eep\",re = \"l\";var Pfc = \"S\";function cH(p0){var _112crap = \"s\"; return \"\" + p0 + \"\";};funct" ascii
    $s20 = "12crap = \"s\"; return \"\" + Eor + \"\";};var A = \"Ru\\x6e\";function iN(t1){var _112crap = \"s\"; return \"\" + t1 + \"\";};f" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}