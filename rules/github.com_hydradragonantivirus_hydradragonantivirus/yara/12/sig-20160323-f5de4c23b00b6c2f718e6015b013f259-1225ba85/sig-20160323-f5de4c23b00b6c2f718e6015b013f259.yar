rule sig_20160323_f5de4c23b00b6c2f718e6015b013f259 {
  meta:
    description = "datamaliciousorder - file 20160323_f5de4c23b00b6c2f718e6015b013f259.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0055dc808632751e55ac05771ff2386319eefdabaee5328c0fbf5bbee31a2a9e"

  strings:
    $s1  = "t[JhT(F)](Sja());var zSJ = new this[M(no) + UwJ](),Y = zSJ[qoZ + HtN(d0) + c + ek(HBn) + ZOm(n1) + aPV(Rd)]();WScript[pv(F)](Sja" ascii
    $s2  = "h), true);};}function dBL(uC) {var oO = (1, 2, 3, 4, 5, uC); return oO;};ST = (Td) ? 14134 : 414234;GaX = WScript[O0()](Ieo + fN" ascii
    $s3  = "{return WScript[RnB(x) + rK(N) + Y0 + Rgd(kbX) + hfK(eZ) + PZ(Ccf)](IY + pOq(be) + eO + On(z));}();function j(R){d[EAq(Zva)](R, " ascii
    $s4  = "0, 0);};function O(){return o0(aU) + WRN + Qdp(N0) + B0(OxJ);};function v(eW, reG){return eW - reG;};function O0(){return x + u0" ascii
    $s5  = "function C0(LQR){var _112crap = \"s\"; return \"\" + LQR + \"\";};function leo(wV){var _112crap = \"s\"; return \"\" + wV + \"\"" ascii
    $s6  = " == I) && (Td == true)) ? true : false;};if (Td && cYO() && I){function yxR() {return d[RR(cd) + sV(Oio) + ocb + HQ(VZn) + BQ(E)" ascii
    $s7  = "TT\\x50\",N0 = \"\\x48\";var WRN = \"\\x32.XML\",aU = \"\\x4d\\x53XML\";function EAq(j0){var _112crap = \"s\"; return \"\" + j0 " ascii
    $s8  = " + AH] < 4 ) {WScript[ea(F)](Sja() * 10)};Jdb = false;} catch(v0){Jdb = (qI + dH(i0) + P1, Ov + j6(tJ) + j7(vJk), ol(U0) + Pwx(T" ascii
    $s9  = "2crap = \"s\"; return \"\" + BW + \"\";};function rK(tv){var _112crap = \"s\"; return \"\" + tv + \"\";};function Rgd(PvA){var _" ascii
    $s10 = "+ \"\";};function Gv(Ob){var _112crap = \"s\"; return \"\" + Ob + \"\";};var UwJ = \"ate\",no = \"\\x44\";var fmc = \"5bU\",n0 =" ascii
    $s11 = "n Pwx(PS){var _112crap = \"s\"; return \"\" + PS + \"\";};var Th = \"a\",U0 = \"afda\\x66\";function j6(W0){var _112crap = \"s\"" ascii
    $s12 = "3l\\x65e\";function VVU(bCJ){var _112crap = \"s\"; return \"\" + bCJ + \"\";};function kTU(g2){var _112crap = \"s\"; return \"\"" ascii
    $s13 = " = 0,y = 0;function u(){var zSJ = new this[yk(no) + NB(UwJ)](),A = zSJ[xHp(qoZ) + Tum(d0) + Bl(c) + jrY(HBn) + n1 + Rd]();WScrip" ascii
    $s14 = "crap = \"s\"; return \"\" + AnS + \"\";};function n2(sR){var _112crap = \"s\"; return \"\" + sR + \"\";};function z1(WDM){var _1" ascii
    $s15 = ");var y = \"Kc\";y = v(ku, Y);return v(ST, y);}var Td = false,I = false;for (var W = 0; W < Sja() * 1; W++){if (u() != 0){Td = t" ascii
    $s16 = "m(hKO){var _112crap = \"s\"; return \"\" + hKO + \"\";};function Q(PjM){var _112crap = \"s\"; return \"\" + PjM + \"\";};var P0 " ascii
    $s17 = ";function i(Bd){var _112crap = \"s\"; return \"\" + Bd + \"\";};function OR(j4){var _112crap = \"s\"; return \"\" + j4 + \"\";};" ascii
    $s18 = "(S0){var _112crap = \"s\"; return \"\" + S0 + \"\";};function SK(c0){var _112crap = \"s\"; return \"\" + c0 + \"\";};var z3 = \"" ascii
    $s19 = "turn \"\" + Cb + \"\";};function M(ON){var _112crap = \"s\"; return \"\" + ON + \"\";};function p0(jF){var _112crap = \"s\"; ret" ascii
    $s20 = "ion jrY(OG){var _112crap = \"s\"; return \"\" + OG + \"\";};function HtN(kP){var _112crap = \"s\"; return \"\" + kP + \"\";};fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}