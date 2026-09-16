rule sig_20160323_621cd9078fb8e640aa7e3987ef6b6ddd {
  meta:
    description = "datamaliciousorder - file 20160323_621cd9078fb8e640aa7e3987ef6b6ddd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "294edcb9a383acb4ebbcce4c36ee619366c02832be155b2b69751680370d1ab1"

  strings:
    $s1  = "function Mqf(j4){var _112crap = \"s\"; return \"\" + j4 + \"\";};function GzR(YV){var _112crap = \"s\"; return \"\" + YV + \"\";" ascii
    $s2  = " = function fP() {return WScript[QGr(Y0) + we(kk) + Q + O(LS)](DnQ + yFp(s) + zGZ(H) + yRa(hwl) + AZE(BIp));}();function q(Wd){T" ascii
    $s3  = "(m) + ef(nS) + Py + Yqb;}; a = HP(); q0 = WScript[Zvu(Y0) + kk + AL(Q) + b(LS)](a); var eVs = true; while (eVs){try {q0[Efq(hb)]" ascii
    $s4  = "Z + G1]();WScript[CfY + E1 + f0](L());var EMw = new this[F(wUd)](),e = EMw[cF(xTv) + zSM(ul) + PPX(Cun) + qpQ(U0) + Xg(L1) + HbK" ascii
    $s5  = " wr(G1)]();WScript[CfY + o0(E1) + MPI(f0)](L());var EMw = new this[wUd](),n = EMw[DyS(xTv) + f(ul) + Cun + CiR(U0) + sU(L1) + LJ" ascii
    $s6  = "x(p2){var _112crap = \"s\"; return \"\" + p2 + \"\";};var Qg = \"GET\";function Efq(dmd){var _112crap = \"s\"; return \"\" + dmd" ascii
    $s7  = " \"getUT\";function F(d){var _112crap = \"s\"; return \"\" + d + \"\";};var wUd = \"Da\\x74\\x65\",feq = \"e\\x63t\";var g0 = \"" ascii
    $s8  = "bL[CWa(XaY)](Wd, 0, 0);};function HP(){return L0(G) + YWO(ma) + DYk(p0) + T(cX);};function E(ay, wKg){return ay - wKg;};function" ascii
    $s9  = " \"Run\";function yFp(cKq){var _112crap = \"s\"; return \"\" + cKq + \"\";};function zGZ(R0){var _112crap = \"s\"; return \"\" +" ascii
    $s10 = "gs\" + 123313 * PR + paU; break;}}function lDX() {return ((kRv == z) && (kRv == true)) ? true : false;};if (kRv && lDX() && z){f" ascii
    $s11 = "AUp = \"i\\x2ec\",L2 = \"ar\";var Qe0 = \"p\\x61z\",JWw = \"y\";var t3 = \"reko\",zGw = \"\\x69\";var B1 = \"p:\\x2f\\x2ft\",I0 " ascii
    $s12 = "us(fpR)]();while (q0[mTv(Q1) + fUl(UEE) + HM(CP)] < 4 ) {WScript[f1(CfY) + t1(E1) + f0](L() * 10)};eVs = false;} catch(Y){eVs = " ascii
    $s13 = "\\x74\"+\"\"](3),SX = \"o\\x70\\x65\";function QEE(qU){var _112crap = \"s\"; return \"\" + qU + \"\";};function HpR(ES){var _112" ascii
    $s14 = ";};function Li(u1){var _112crap = \"s\"; return \"\" + u1 + \"\";};function rsd(ajG){var _112crap = \"s\"; return \"\" + ajG + " ascii
    $s15 = "muN){var _112crap = \"s\"; return \"\" + muN + \"\";};function f1(p1){var _112crap = \"s\"; return \"\" + p1 + \"\";};function t" ascii
    $s16 = "crap = \"s\"; return \"\" + r + \"\";};function HbK(rqp){var _112crap = \"s\"; return \"\" + rqp + \"\";};function xC(hKK){var _" ascii
    $s17 = "cha\"+\"\\x72\"+\"A\"+\"\\x74\"+\"\"](2);function tL(fM){var _112crap = \"s\"; return \"\" + fM + \"\";};function q1(zAW){var _1" ascii
    $s18 = "\"\" + LGq + \"\";};function z0(snD){var _112crap = \"s\"; return \"\" + snD + \"\";};function lw(Ms){var _112crap = \"s\"; retu" ascii
    $s19 = " \"\";};function e0(UwA){var _112crap = \"s\"; return \"\" + UwA + \"\";};function yP(OF){var _112crap = \"s\"; return \"\" + OF" ascii
    $s20 = "Z){var _112crap = \"s\"; return \"\" + wZ + \"\";};var CP = \"state\",UEE = \"\\x65ady\";var Q1 = \"r\";function oed(ui){var _11" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}