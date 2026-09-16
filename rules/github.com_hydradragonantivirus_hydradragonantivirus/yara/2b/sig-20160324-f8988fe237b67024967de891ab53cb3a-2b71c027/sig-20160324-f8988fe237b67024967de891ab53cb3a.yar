rule sig_20160324_f8988fe237b67024967de891ab53cb3a {
  meta:
    description = "datamaliciousorder - file 20160324_f8988fe237b67024967de891ab53cb3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb3bf989f12b5f38efb09dbaaf8f95a04a49be13812ab35f41e944511f4401bd"

  strings:
    $s1  = "function M1(P0){var _112crap = \"s\"; return \"\" + P0 + \"\";};var gC = \"\\x65\",oS = \"clo\\x73\";function R1(BK){var _112cra" ascii
    $s2  = "= \"s\"; return \"\" + B + \"\";};var gG = \"%\\x2f\",Hp = \"\\x25TEMP\";var Cw = \"\\x73\",O = \"ri\\x6eg\";var d1 = \"\\x6e\\x" ascii
    $s3  = "XMLHTTP\";var cyU = 2123213,K = 0;function Z(e){l[wo](e, K, K);};function R(){return HHx;};function u(qU, CjZ){return qU - CjZ;}" ascii
    $s4  = ",u0 = 0;function ls(){var xo = new this[d(j)](),OD = xo[gIO + Fq(evN) + zal + f]();WScript[Wsv + eL](VRY());var xo = new this[jV" ascii
    $s5  = "oFX + VaM + d1 + O + Cw](ZUb(Hp) + gG) + qEn(TT) + pHc + v + F0;}; ZI = R(); V = WScript[Z0](ZI); var Qg = 1; while (Qg){try {V[" ascii
    $s6  = "tp:\",PJ = \"\\x47ET\";function Ps(Kr){var _112crap = \"s\"; return \"\" + Kr + \"\";};var H = \"ope\\x6e\";function qEn(ZIc){va" ascii
    $s7  = "H](PJ, wi + jS + RU(DZ) + pF(hlB) + W(P) + Qg0 + M0, false);V[sAf]();aLo = \"Sleep\";while (V[KHU + Sv + voG] < 4 ) {WScript[aLo" ascii
    $s8  = "r M = false,Z0 = \"CreateObject\";var l = function CkT() {return WScript[Z0](K0 + YRO + F(mV));}();var gEL = 123213,HHx = \"MSXM" ascii
    $s9  = "R(j)](),Kdz = xo[gIO + evN + zal + D(f)]();WScript[Wsv + eL](VRY());var xo = new this[j](),T = xo[Je(gIO) + IZV(evN) + zal + f](" ascii
    $s10 = "Lu + u0; break;}}function gS() {return ((EM == true) && (EM == I)) ? 1 : K;};if (EM && gS() && I){function gDi() {return l[T0 + " ascii
    $s11 = "n \"\" + L + \"\";};function pF(MvC){var _112crap = \"s\"; return \"\" + MvC + \"\";};function W(e1){var _112crap = \"s\"; retur" ascii
    $s12 = ",zU = \"\\x67etU\";var qWc = \"\\x44\\x61te\",eL = \"\\x70\";var Wsv = \"S\\x6c\\x65\\x65\";function Fq(Y){var _112crap = \"s\";" ascii
    $s13 = "RY() * 1; h++){if (ls() != K){EM = true; u0 = \"07t9gasdf76ags\" + 123313 * pLu + u0; I = true; u0 = \"07t9gasdf76ags\" + 123313" ascii
    $s14 = "urn \"\" + gS0 + \"\";};var b = \"\\x65\",HGT = \"\\x77\\x72it\";function Eln(vL){var _112crap = \"s\"; return \"\" + vL + \"\";" ascii
    $s15 = "on IZV(Cg){var _112crap = \"s\"; return \"\" + Cg + \"\";};var f = \"\\x6fnds\",zal = \"l\\x69sec\";var evN = \"C\\x4dil\",gIO =" ascii
    $s16 = "urn \"\" + BK + \"\";};var nAE = \"\\x6fFile\",Nn = \"\\x53ave\\x54\";function W0(jPR){var _112crap = \"s\"; return \"\" + jPR +" ascii
    $s17 = "ction d(n){var _112crap = \"s\"; return \"\" + n + \"\";};function jVR(Ni){var _112crap = \"s\"; return \"\" + Ni + \"\";};var j" ascii
    $s18 = "\"\";};function D(e0){var _112crap = \"s\"; return \"\" + e0 + \"\";};function Je(pVH){var _112crap = \"s\"; return \"\" + pVH +" ascii
    $s19 = "ar I0 = \"fa\\x64\\x66a\";function ynj(qhf){var _112crap = \"s\"; return \"\" + qhf + \"\";};var pT = \"\\x61\",s = \"as\\x64f\"" ascii
    $s20 = "\"s\"; return \"\" + ZIc + \"\";};var F0 = \"\\x2ee\\x78e\",v = \"t\\x56Ph\";var pHc = \"v\\x70yX\",TT = \"OM\\x30w\";function Z" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}