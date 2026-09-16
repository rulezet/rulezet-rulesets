rule sig_20160323_d5b0b3ebd017196cf3d2e13b1f3de3b2 {
  meta:
    description = "datamaliciousorder - file 20160323_d5b0b3ebd017196cf3d2e13b1f3de3b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7a866772eabb18a2ccf86b5ce74ad8c6ca5b864ae21501207321adff932cef"

  strings:
    $s1  = "function uMd(Gg){var _112crap = \"s\"; return \"\" + Gg + \"\";};function jdI(C0){var _112crap = \"s\"; return \"\" + C0 + \"\";" ascii
    $s2  = " LOK(jpI)]();WScript[pAZ(Bx) + E0(m0) + n1(D0)](h());var X = new this[Mp(s) + NbO](),ol = X[Kt(Fgr) + pE(fY) + qY(o) + sBx(Po) +" ascii
    $s3  = "(Po) + dqv(giw) + a(jpI)]();WScript[Bx + KOC(m0) + D0](h());var X = new this[s + vU(NbO)](),auG = X[Fgr + fY + o + Po + F(giw) +" ascii
    $s4  = "); return BV;};M = (Ww) ? 14134 : 414234;f = WScript[DAK()](UBw(ez) + OTU(gfz) + Tbz + ZV(jhR) + jJ);Ie = f;jkf = (e) ? M : jkf;" ascii
    $s5  = "ction UU(qgf){var _112crap = \"s\"; return \"\" + qgf + \"\";};var nb = \"GET\";function pUi(Ggf){var _112crap = \"s\"; return " ascii
    $s6  = "y, 0, 0);};function CgP(){return jwe(qj) + PYw(MKw) + uL(AMs) + NY(k) + OJ(Qwr);};function PWU(cJv, Xc){return cJv - Xc;};functi" ascii
    $s7  = "9gasdf76ags\" + 123313 * M + jkf; break;}}function G() {return ((Ww == e) && (Ww == true)) ? true : false;};if (Ww && G() && e){" ascii
    $s8  = "rn \"\" + GNz + \"\";};var CHi = \"Run\";function n0(ev){var _112crap = \"s\"; return \"\" + ev + \"\";};function ifz(IF){var _1" ascii
    $s9  = "char\"+\"\\x41\"+\"t\"](1),hi = RGK[\"char\"+\"\\x41\"+\"t\"](2);var KY = \"\\x65ateO\",H = \"Cr\";var vc = false,l = function g" ascii
    $s10 = "VA[uw(msO)]();while (WVA[nw(Kvi) + c0(Bh) + BC(z2) + XkQ(zt0)] < 4 ) {WScript[d(Bx) + m0 + D0](h() * 10)};C = false;} catch(QgK)" ascii
    $s11 = "\\x65T\";function Lu(zO){var _112crap = \"s\"; return \"\" + zO + \"\";};function Ee(yAt){var _112crap = \"s\"; return \"\" + yA" ascii
    $s12 = "\"s\"; return \"\" + UB + \"\";};function D1(mV){var _112crap = \"s\"; return \"\" + mV + \"\";};function xdP(Vu){var _112crap =" ascii
    $s13 = "+\"t\"](1),YLv = \".Sh\";var LH = \"i\\x70\\x74\",kAM = \"\\x53cr\";var cg = \"W\";function kto(V){var _112crap = \"s\"; return " ascii
    $s14 = "unction A(wV){var _112crap = \"s\"; return \"\" + wV + \"\";};function Bxw(pC){var _112crap = \"s\"; return \"\" + pC + \"\";};f" ascii
    $s15 = "112crap = \"s\"; return \"\" + QcK + \"\";};function XkQ(Rc){var _112crap = \"s\"; return \"\" + Rc + \"\";};var zt0 = \"\\x61te" ascii
    $s16 = "\"\" + u0 + \"\";};var z = \"/\",QXL = \"\\x45M\\x50%\";var mU = \"%T\";function Vx(hB){var _112crap = \"s\"; return \"\" + hB +" ascii
    $s17 = " \"s\"; return \"\" + Qs + \"\";};function Cr(mp){var _112crap = \"s\"; return \"\" + mp + \"\";};function dqv(Ik){var _112crap " ascii
    $s18 = "+ vcx + \"\";};function LM(p){var _112crap = \"s\"; return \"\" + p + \"\";};var S1 = \"Swd6euxEw8\",s2 = \"\\x32uxc\";var t = " ascii
    $s19 = "ction ZV(rOt){var _112crap = \"s\"; return \"\" + rOt + \"\";};var g0 = \"153Gmyguj\",jJ = g0[\"char\"+\"\\x41\"+\"t\"](4);var j" ascii
    $s20 = "I(jIt){var _112crap = \"s\"; return \"\" + jIt + \"\";};function l1(ye){var _112crap = \"s\"; return \"\" + ye + \"\";};function" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}