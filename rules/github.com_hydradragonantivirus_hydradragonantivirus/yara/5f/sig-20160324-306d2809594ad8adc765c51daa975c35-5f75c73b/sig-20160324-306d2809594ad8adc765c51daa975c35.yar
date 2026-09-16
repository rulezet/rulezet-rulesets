rule sig_20160324_306d2809594ad8adc765c51daa975c35 {
  meta:
    description = "datamaliciousorder - file 20160324_306d2809594ad8adc765c51daa975c35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51edb5d801dc981a4dde1b43118abad1c66dd4b1363dae8e8270a9b2c89e53c2"

  strings:
    $s1  = "rn WScript[Rk](IaO + Flk + Mp(o));}();var YC = 123213,cvG = \"MSXML2.XMLHTTP\";var l = 2123213,hL = 0;function Z(Aug){toU[yZ](Au" ascii
    $s2  = "function Mb(yjc){var _112crap = \"s\"; return \"\" + yjc + \"\";};var oxa = \"\\x65\",MWD = \"\\x63los\";var oK = \"\\x6ce\",LCc" ascii
    $s3  = "* hTI + eLN; ptr = true; eLN = \"07t9gasdf76ags\" + 123313 * hTI + eLN; break;}}function eN() {return ((i == true) && (i == ptr)" ascii
    $s4  = " mu = LC(); Ng = WScript[Rk](mu); var Cs = 1; while (Cs){try {Ng[ZA](ABc, a0 + v + GI + ni + PZ(R) + uo + Uh + Wh(UR), false);Ng" ascii
    $s5  = ", 2);};}function PN(Us) {var qKu = (1, 2, 3, 4, 5, Us); return qKu;};q = WScript[u()](D + Mg + q1(q0));mu = q;mu[(ZA)]();mu[pc] " ascii
    $s6  = "gj[J + zp + QdV + Ug + e]();WScript[p(x)](F());var gj = new this[xV](),y = gj[J + zp + QdV + Ug + e]();WScript[x](F());var gj = " ascii
    $s7  = " hL, hL);};function LC(){return cvG;};function EjL(DfU, AK){return DfU - AK;};function u(){return Rk;};/*@cc_on  @if (@_win32 ||" ascii
    $s8  = "? 1 : hL;};if (i && eN() && ptr){function YJA() {return toU[oc + ej + MXX + Y + p2(mre) + ley](E(Gb) + Z0(xQz)) + f + X0 + Kx;};" ascii
    $s9  = "[vHp]();V0 = \"Sleep\";while (Ng[Q + V1 + yrp] < 4 ) {WScript[V0](F() * 10)};Cs = hL;} catch(DY){Cs = (I, w(dZ) + nK, h + UAj(qh" ascii
    $s10 = "ar Wm = \"MS\\x58ML\";function Mp(j){var _112crap = \"s\"; return \"\" + j + \"\";};var o = \"\\x65\\x6cl\",Flk = \"pt\\x2eSh\";" ascii
    $s11 = " = \"s\"; return \"\" + i0 + \"\";};var ley = \"\\x73\",mre = \"ri\\x6e\\x67\";var Y = \"e\\x6etSt\",MXX = \"ir\\x6f\\x6e\\x6d\"" ascii
    $s12 = " \"\";};function Z0(dxY){var _112crap = \"s\"; return \"\" + dxY + \"\";};var xQz = \"\\x25/\",Gb = \"%TEM\\x50\";function p2(i0" ascii
    $s13 = " eLN);}var i = false,ptr = false;for (var BR = hL; BR < F() * 1; BR++){if (V() != hL){i = true; eLN = \"07t9gasdf76ags\" + 12331" ascii
    $s14 = "f\";function w(mL){var _112crap = \"s\"; return \"\" + mL + \"\";};var nK = \"asd\\x66\",dZ = \"fad\\x66\";var I = \"as\\x64f\\x" ascii
    $s15 = ",fq = \"wri\\x74\";var pc = \"\\x74\\x79pe\",A = \"\\x6fpen\";function q1(a1){var _112crap = \"s\"; return \"\" + a1 + \"\";};va" ascii
    $s16 = "function Mb(yjc){var _112crap = \"s\"; return \"\" + yjc + \"\";};var oxa = \"\\x65\",MWD = \"\\x63los\";var oK = \"\\x6ce\",LCc" ascii
    $s17 = "\",Mg = \".\\x53t\\x72e\";var D = \"AD\\x4fDB\";function UAj(cr){var _112crap = \"s\"; return \"\" + cr + \"\";};var qhL = \"\\x" ascii
    $s18 = "\"; return \"\" + x0 + \"\";};function Wh(u0){var _112crap = \"s\"; return \"\" + u0 + \"\";};var UR = \"\\x78j3sa\",Uh = \"\\x6" ascii
    $s19 = " = \"ope\\x6e\";var Kx = \".e\\x78\\x65\",X0 = \"M\\x45\\x698\\x66\";var f = \"o\\x41r\\x4d9\";function E(n){var _112crap = \"s" ascii
    $s20 = "tU\\x54\";var Lag = \"\\x44ate\";function p(Hyo){var _112crap = \"s\"; return \"\" + Hyo + \"\";};var x = \"Slee\\x70\",e = \"" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}