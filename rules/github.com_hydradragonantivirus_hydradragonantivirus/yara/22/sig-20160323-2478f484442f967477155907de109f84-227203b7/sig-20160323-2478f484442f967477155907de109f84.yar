rule sig_20160323_2478f484442f967477155907de109f84 {
  meta:
    description = "datamaliciousorder - file 20160323_2478f484442f967477155907de109f84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62059ead3cedf9cf6bd724d5d505f3217e8c2ede36d191e649c88a48bc26a4cb"

  strings:
    $s1  = "function Xx(Gh){var _112crap = \"s\"; return \"\" + Gh + \"\";};var H1 = \"c\\x6cose\";function Hb(pbT){var _112crap = \"s\"; re" ascii
    $s2  = ";function yG(ihZ){var _112crap = \"s\"; return \"\" + ihZ + \"\";};var zcc = \"%\\x2f\",h2 = \"%TEMP\";function LTp(Hv){var _112" ascii
    $s3  = " + \"\";};function dIh(HY){var _112crap = \"s\"; return \"\" + HY + \"\";};var u2 = \"n:\",V = \"x\";var Ht = \"\\x37jc\",Q = \"" ascii
    $s4  = " aX(d1), WMe + l(DQ), true);};}function FZY(D) {var fm = (1, 2, 3, 4, 5, D); return fm;};qIe = (u) ? 14134 : 414234;HT = WScript" ascii
    $s5  = "(c0) + k0(S1);}; g = NfP(); e0 = WScript[rGI + y + lr + lV(J0)](g); var Fz = true; while (Fz){try {e0[oX0(dK) + jK(ZD)](y0, eQ(g" ascii
    $s6  = " BGO(aD)]();WScript[kc(d)](CKW());var I = new this[ENl(OEu)](),TjE = I[UJz + F + OY(D0) + wA(OIL) + xJ(n) + vTi(aD)]();var qIe =" ascii
    $s7  = "x74eO\",rGI = \"\\x43\\x72e\";var E = false,J = function e() {return WScript[NR(rGI) + Qu(y) + s(lr) + u0(J0)](EE(nIA) + UCK + I" ascii
    $s8  = "0(D0) + xM(OIL) + n + hxI(aD)]();WScript[Jv(d)](CKW());var I = new this[OEu](),FYA = I[UJz + WSZ(F) + TL(D0) + c(OIL) + OIG(n) +" ascii
    $s9  = "3313 * qIe + gPS; break;}}function HV() {return ((u == Ef) && (u == true)) ? true : false;};if (u && HV() && Ef){function xk() {" ascii
    $s10 = "(e0[cyX(M) + V0(bA) + kx(qkL)] < 4 ) {WScript[cNY(d)](CKW() * 10)};Fz = false;} catch(Ml){Fz = (I1(vQ) + F0(SZ) + rDy, t1(ndj) +" ascii
    $s11 = " _112crap = \"s\"; return \"\" + mY + \"\";};function cNY(KVB){var _112crap = \"s\"; return \"\" + KVB + \"\";};var d = \"\\x53" ascii
    $s12 = "bT + \"\";};function kE(zs){var _112crap = \"s\"; return \"\" + zs + \"\";};function dhK(G1){var _112crap = \"s\"; return \"\" +" ascii
    $s13 = " D1(dLC){var _112crap = \"s\"; return \"\" + dLC + \"\";};function xF(o){var _112crap = \"s\"; return \"\" + o + \"\";};function" ascii
    $s14 = "; return \"\" + bfC + \"\";};function OkE(L2){var _112crap = \"s\"; return \"\" + L2 + \"\";};function xk0(tQ){var _112crap = \"" ascii
    $s15 = ",UJz = \"g\\x65t\\x55T\";function eD(Zu){var _112crap = \"s\"; return \"\" + Zu + \"\";};function ENl(mDO){var _112crap = \"s\";" ascii
    $s16 = "ap = \"s\"; return \"\" + J1 + \"\";};function S(ib){var _112crap = \"s\"; return \"\" + ib + \"\";};function hbu(oMB){var _112c" ascii
    $s17 = "on Qu(h){var _112crap = \"s\"; return \"\" + h + \"\";};function s(lbI){var _112crap = \"s\"; return \"\" + lbI + \"\";};functio" ascii
    $s18 = ";};function Ovo(Xw){var _112crap = \"s\"; return \"\" + Xw + \"\";};function U(Ic){var _112crap = \"s\"; return \"\" + Ic + \"\"" ascii
    $s19 = "x74\";var GSO = \"nW5Ih3\",y1 = GSO[\"charA\"+\"\\x74\"+\"\"](0);var UZ = \"ope\";function wJH(STX){var _112crap = \"s\"; return" ascii
    $s20 = "ction jK(wDi){var _112crap = \"s\"; return \"\" + wDi + \"\";};function Cw(H0){var _112crap = \"s\"; return \"\" + H0 + \"\";};f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}