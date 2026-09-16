rule sig_20160324_03c6297b7fe094703c2034d0b6f302de {
  meta:
    description = "datamaliciousorder - file 20160324_03c6297b7fe094703c2034d0b6f302de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc051a2d1f765d5232f9586bb85fafac2fa95afefb4f32e4f052b9e6f85fd8b3"

  strings:
    $s1  = " WScript[L](PPN + p + R0);}();var eue = 123213,YO = \"MSXML2.XMLHTTP\";var S = 2123213,uAE = 0;function pg(QE){J[y](QE, uAE, uAE" ascii
    $s2  = ", Du + vnp, 2);};}function PQ(dEw) {var Qw = (1, 2, 3, 4, 5, dEw); return Qw;};R = WScript[t()](OFP + E0 + VJX);m = R;m[(gv)]();" ascii
    $s3  = " m = Uo(); XK = WScript[L](m); var ghm = 1; while (ghm){try {XK[gv](ov(o), poq(iou) + NK + OD + M0(z) + K1 + hhp(r), false);XK[d" ascii
    $s4  = "xo + M + qKP(Z)]();WScript[Esa(PXe)](rs());var HlJ = new this[Efp](),g = HlJ[p0(Y) + pH(xo) + M + Z]();WScript[PXe](rs());var Hl" ascii
    $s5  = "function x(B){var _112crap = \"s\"; return \"\" + B + \"\";};var hB = \"c\\x6cose\";function RL(KD){var _112crap = \"s\"; return" ascii
    $s6  = "};if (mS && zzo() && bIu){function qQ() {return J[vL + oa(oY) + g0 + k0 + v0 + dpa](Sgs(PR) + qUL(zl)) + pO + m0(aui) + U + G;};" ascii
    $s7  = " q; bIu = true; q = \"07t9gasdf76ags\" + 123313 * SQi + q; break;}}function zzo() {return ((mS == true) && (mS == bIu)) ? 1 : uA" ascii
    $s8  = "]();vxW = \"Sleep\";while (XK[Ko + bR + M1(We)] < 4 ) {WScript[vxW](rs() * 10)};ghm = uAE;} catch(utJ){ghm = (mDm + pEy, A + Q(k" ascii
    $s9  = "var OFP = \"\\x41DOD\",vnp = \"\\x61\";var Du = \"afda\\x66\";function Q(ty){var _112crap = \"s\"; return \"\" + ty + \"\";};var" ascii
    $s10 = "ar _112crap = \"s\"; return \"\" + evV + \"\";};function K(qb){var _112crap = \"s\"; return \"\" + qb + \"\";};var Z = \"on\\x64" ascii
    $s11 = "112crap = \"s\"; return \"\" + E + \"\";};var dpa = \"\\x6egs\",v0 = \"\\x53tr\\x69\";var k0 = \"\\x6dent\",g0 = \"iro\\x6e\";va" ascii
    $s12 = "_112crap = \"s\"; return \"\" + rS + \"\";};var o = \"G\\x45T\",gv = \"\\x6fp\\x65n\";function m0(qe){var _112crap = \"s\"; retu" ascii
    $s13 = "function x(B){var _112crap = \"s\"; return \"\" + B + \"\";};var hB = \"c\\x6cose\";function RL(KD){var _112crap = \"s\"; return" ascii
    $s14 = "ec\";var xo = \"T\\x43\\x4dil\",Y = \"g\\x65t\\x55\";function NN(v){var _112crap = \"s\"; return \"\" + v + \"\";};var Efp = \"" ascii
    $s15 = " xuu + \"\";};function qUL(u){var _112crap = \"s\"; return \"\" + u + \"\";};var zl = \"\\x25/\",PR = \"\\x25TE\\x4d\\x50\";func" ascii
    $s16 = "+ \"\";};function M0(zKJ){var _112crap = \"s\"; return \"\" + zKJ + \"\";};function hhp(SUb){var _112crap = \"s\"; return \"\" +" ascii
    $s17 = "A = \"\\x66ad\\x66a\";var pEy = \"\\x61\",mDm = \"\\x61sdf\";function M1(NRr){var _112crap = \"s\"; return \"\" + NRr + \"\";};v" ascii
    $s18 = " xt = true;  @end@*/if (xt){function rs(){return 22;};var SQi = 0,q = 0;function F(){var HlJ = new this[NN(Efp)](),dU = HlJ[Y + " ascii
    $s19 = "bR = \"\\x79sta\";var Ko = \"\\x72ead\",Hu = \"\\x53le\\x65\\x70\";var d = \"se\\x6ed\";function poq(dXU){var _112crap = \"s\"; " ascii
    $s20 = " mS = false,bIu = false;for (var vh = uAE; vh < rs() * 1; vh++){if (F() != uAE){mS = true; q = \"07t9gasdf76ags\" + 123313 * SQi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}