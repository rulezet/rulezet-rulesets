rule sig_20160324_ddfa0d7b7ec79596e795d6a45f81c0cf {
  meta:
    description = "datamaliciousorder - file 20160324_ddfa0d7b7ec79596e795d6a45f81c0cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af9a894c6efe1ecbb4a9cb1a7c59068158b45cbb51a689b8e4e4f4be23ec2399"

  strings:
    $s1  = "TK, 2);};}function Np(MP) {var jNx = (1, 2, 3, 4, 5, MP); return jNx;};Wkl = WScript[g()](WkL + T + K(IP));Tl = Wkl;Tl[(qJ)]();T" ascii
    $s2  = "Mj);}; Tl = oZl(); dR = WScript[z](Tl); var Wdv = 1; while (Wdv){try {dR[qJ](VX, Q1 + yhK + Xmg(z0) + lj + NB, false);dR[OR]();Q" ascii
    $s3  = "LTG + f0]();WScript[vC + qPU](dQH());var YN = new this[sge](),eQK = YN[KOo + rB + LTG + f0]();WScript[RJ(vC) + qPU](dQH());var Y" ascii
    $s4  = "var Smo = \"\\x65\",qy = \"clo\\x73\";function Y0(FAr){var _112crap = \"s\"; return \"\" + FAr + \"\";};var ZHQ = \"l\\x65\",Vg " ascii
    $s5  = " * zBh + U; Nx = true; U = \"07t9gasdf76ags\" + 123313 * zBh + U; break;}}function VjR() {return ((nq == true) && (nq == Nx)) ? " ascii
    $s6  = "f) + vs(jo) + Uz);}();var NA = 123213,NER = \"MSXML2.XMLHTTP\";var M = 2123213,otb = 0;function Nb(Bp){bkr[FZ(AB)](Bp, otb, otb)" ascii
    $s7  = ": otb;};if (nq && VjR() && Nx){function q() {return bkr[F0(hd) + pf + u + y + q0 + vb](ih + k) + Kkn(wQR) + V + tSB(Unk) + eHr(x" ascii
    $s8  = " \"\\x65ct\";var lh = \"eOb\\x6a\",Y = \"C\\x72\\x65at\";var uvk = false,z = \"CreateObject\";var bkr = function Oz() {return WS" ascii
    $s9  = "L = \"Sleep\";while (dR[rIq + Dp + nX(b)] < 4 ) {WScript[QL](dQH() * 10)};Wdv = otb;} catch(dhx){Wdv = (O + e(u0), om + aD, f1 +" ascii
    $s10 = "};function vs(QcB){var _112crap = \"s\"; return \"\" + QcB + \"\";};var Uz = \"\\x68ell\",jo = \"\\x70t\\x2e\\x53\";var f = \"" ascii
    $s11 = "B + \"\";};var s0 = \"ty\\x70e\",sAy = \"op\\x65n\";function K(NFf){var _112crap = \"s\"; return \"\" + NFf + \"\";};var IP = \"" ascii
    $s12 = "nction RJ(xXE){var _112crap = \"s\"; return \"\" + xXE + \"\";};var qPU = \"\\x70\",vC = \"S\\x6cee\";var f0 = \"n\\x64\\x73\",L" ascii
    $s13 = "{var _112crap = \"s\"; return \"\" + OUd + \"\";};var GIs = \"\\x65\",Ow = \"\\x77ri\\x74\";function Nt(HB){var _112crap = \"s\"" ascii
    $s14 = "var nq = false,Nx = false;for (var vaF = otb; vaF < dQH() * 1; vaF++){if (ILe() != otb){nq = true; U = \"07t9gasdf76ags\" + 1233" ascii
    $s15 = "N = new this[sge](),D = YN[KOo + rB + LTG + f0]();var zBh = \"yX\";zBh = v(eQK, KR);var U = \"apl\";U = v(D, eQK);return v(zBh, " ascii
    $s16 = "crap = \"s\"; return \"\" + GG + \"\";};function eHr(Wz){var _112crap = \"s\"; return \"\" + Wz + \"\";};var xMj = \"x\\x65\",Un" ascii
    $s17 = "x63o\";var rB = \"CM\\x69l\\x6c\",KOo = \"\\x67etU\\x54\";var sge = \"\\x44ate\";function FZ(wJ){var _112crap = \"s\"; return \"" ascii
    $s18 = " true;  @end@*/if (uvk){function dQH(){return 22;};var zBh = 0,U = 0;function ILe(){var YN = new this[sge](),KR = YN[KOo + rB + " ascii
    $s19 = "ar AB = \"\\x52un\",lU = \"L\\x48TTP\";var Ngt = \"L\\x32.XM\",VM = \"MS\\x58\\x4d\";function ym(VF){var _112crap = \"s\"; retur" ascii
    $s20 = "var Stm = \"\\x53\\x61\\x76e\",TtK = \"\\x69\\x6fn\";var cYr = \"pos\\x69t\";function CH(EV){var _112crap = \"s\"; return \"\" +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}