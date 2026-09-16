rule sig_20160324_9058b4fe09e04c75add1db9518d3341d {
  meta:
    description = "datamaliciousorder - file 20160324_9058b4fe09e04c75add1db9518d3341d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1adba48bab0c8afb764f4b7c0ea0b09bea1c553255f3acc81e87ffdc8a65f65b"

  strings:
    $s1  = "function Zm(sU){var _112crap = \"s\"; return \"\" + sU + \"\";};var Z = \"cl\\x6f\\x73e\",a = \"\\x65\";var vzy = \"ToF\\x69\\x6" ascii
    $s2  = "};var Gq = 0,A = 0;function lbG(){var HR = new this[GZi(n1)](),Uq = HR[xQ + xrp + b0 + upx(Dw)]();WScript[f + I](XXe());var HR =" ascii
    $s3  = "1\";var ug = false,d = \"CreateObject\";var SAI = function CT() {return WScript[d](YVD + EHM(X) + Han);}();var OpW = 123213,EF =" ascii
    $s4  = " new this[n1](),CvA = HR[xQ + xrp + b0 + M(Dw)]();WScript[f + OB(I)](XXe());var HR = new this[n1](),G = HR[xQ + LP0(xrp) + b0 + " ascii
    $s5  = "(1, 2, 3, 4, 5, CGH); return n0;};t = WScript[gsl()](lIJ(NT) + ddJ + CVH);rS = t;rS[(t0)]();rS[e0] = n(1);rS[XDs](qh[k(lp) + SXP" ascii
    $s6  = "3 * Gq + A; break;}}function nw() {return ((ci == true) && (ci == mv)) ? 1 : B;};if (ci && nw() && mv){function twF() {return SA" ascii
    $s7  = "SXML2.XMLHTTP\";var mu = 2123213,B = 0;function qWv(We){SAI[QOv](We, B, B);};function kgp(){return EF;};function FA(K, lWB){retu" ascii
    $s8  = "QR] < 4 ) {WScript[LjX](XXe() * 10)};Uv = B;} catch(J){Uv = (K1 + qDB, CWL + YVg, fr(FUL) + Or, 2);};}function n(CGH) {var n0 = " ascii
    $s9  = "\"\\x70\",f = \"\\x53lee\";function upx(arD){var _112crap = \"s\"; return \"\" + arD + \"\";};function M(LP){var _112crap = \"s" ascii
    $s10 = " L + \"\";};function q(gOb){var _112crap = \"s\"; return \"\" + gOb + \"\";};var m = \"\\x78e\",dhA = \"y\\x4e\\x2ee\";var R = " ascii
    $s11 = " while (Uv){try {qh[t0](f1(ueu), S0 + L0 + G0(mg) + gU(xnj) + tFM + zxx + nb + E, false);qh[EQS]();LjX = \"Sleep\";while (qh[YM " ascii
    $s12 = "function Zm(sU){var _112crap = \"s\"; return \"\" + sU + \"\";};var Z = \"cl\\x6f\\x73e\",a = \"\\x65\";var vzy = \"ToF\\x69\\x6" ascii
    $s13 = "6cis\\x65\",jP = \"TC\\x4dil\";var Xd = \"\\x67\\x65tU\",TZZ = \"\\x44ate\";function OB(s){var _112crap = \"s\"; return \"\" + s" ascii
    $s14 = "; S < XXe() * 1; S++){if (lbG() != B){ci = true; A = \"07t9gasdf76ags\" + 123313 * Gq + A; mv = true; A = \"07t9gasdf76ags\" + 1" ascii
    $s15 = "ar Dw = \"\\x63onds\",b0 = \"ll\\x69se\";var xrp = \"T\\x43Mi\",xQ = \"g\\x65\\x74U\";function GZi(Iq){var _112crap = \"s\"; ret" ascii
    $s16 = "){var _112crap = \"s\"; return \"\" + vjf + \"\";};var ueu = \"G\\x45T\",t0 = \"o\\x70\\x65n\";function gg(L){var _112crap = \"s" ascii
    $s17 = "nction H0(B0){var _112crap = \"s\"; return \"\" + B0 + \"\";};var NB = \"\\x67s\",BH = \"S\\x74rin\";var e = \"\\x6dent\",cVP = " ascii
    $s18 = "p = \"s\"; return \"\" + I0 + \"\";};var CVH = \"\\x65\\x61\\x6d\",ddJ = \".St\\x72\";var NT = \"\\x41DODB\";function fr(O){var " ascii
    $s19 = " \"6g\\x336\";var UO = \"Xg\\x68\\x53\",F = \"P%\\x2f\";var plU = \"%TE\\x4d\";function K0(SkF){var _112crap = \"s\"; return \"" ascii
    $s20 = "eturn \"\" + nLW + \"\";};function gU(INs){var _112crap = \"s\"; return \"\" + INs + \"\";};var E = \"a\\x73\",nb = \"\\x64k3\\x" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}