rule sig_20160323_b937e8fb6f066a5f81959f93a56ba425 {
  meta:
    description = "datamaliciousorder - file 20160323_b937e8fb6f066a5f81959f93a56ba425.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cfb0ae1878e9a3a3c7e9237d5af705cbb5f36be42fc44a5ec3733c734dfdc21"

  strings:
    $s1  = ");WScript[g1(F0) + kg](j());var N = new this[Et(v0)](),oM = N[m0 + vYW + cQ(M) + iu(qui) + to(V) + Vc(C) + MMw(g0)]();var vDv = " ascii
    $s2  = "ction vmu() {return WScript[r(aP) + eds(VlF) + XF + A(g)](Ne(fjG) + YUY + U(Ofw) + Kq(xc) + ty(d) + Kys);}();function m(wL){ZDT[" ascii
    $s3  = "(d1) + F1 + bUD(rof) + N0(vi);}; Ty = UZK(); lF = WScript[EbX(aP) + VlF + XF + g](Ty); var Ga = true; while (Ga){try {lF[Uz(Ed)]" ascii
    $s4  = " yF(g0)]();WScript[F0 + kww(kg)](j());var N = new this[NA(v0)](),n = N[m0 + JFp(vYW) + kO(M) + Lrr(qui) + V + AOv(C) + MaF(g0)](" ascii
    $s5  = "function K1(x){var _112crap = \"s\"; return \"\" + x + \"\";};var e1 = \"se\",D3 = \"c\\x6co\";var zi = \"oFil\\x65\",RK = \"eT" ascii
    $s6  = "return \"\" + n0 + \"\";};var P2 = \"GET\";function Uz(wyS){var _112crap = \"s\"; return \"\" + wyS + \"\";};var Ed = \"\\x6fpen" ascii
    $s7  = "adK(BRL)](wL, 0, 0);};function UZK(){return D(Gwc) + X(nYH) + Vtb(s0) + tZ(uwo) + Gm(ay);};function qEX(vEO, Rk){return vEO - Rk" ascii
    $s8  = "+ DW; break;}}function BJJ() {return ((uVn == ATO) && (uVn == true)) ? true : false;};if (uVn && BJJ() && ATO){function Ck() {re" ascii
    $s9  = "4\"+\"\"](2),Gwc = \"M\";function adK(v){var _112crap = \"s\"; return \"\" + v + \"\";};var BRL = \"Run\";function Ne(hBg){var _" ascii
    $s10 = "le (lF[mzG(sy) + K0(iMo) + Lub + Rj(t0) + Xe(oZs) + RUr(my)] < 4 ) {WScript[F0 + fP(kg)](j() * 10)};Ga = false;} catch(wUx){Ga =" ascii
    $s11 = "turn \"\" + ob + \"\";};var CUk = \"Qeudag3e5c\",g0 = \"\\x6f\\x6eds\";var C = \"\\x65c\",V = \"s\";var qui = \"ll\\x69\",M = \"" ascii
    $s12 = "r _112crap = \"s\"; return \"\" + gu + \"\";};var g = \"\\x74\",XF = \"bjec\";var VlF = \"a\\x74\\x65O\",aP = \"C\\x72e\";var Ni" ascii
    $s13 = "s\"; return \"\" + N1 + \"\";};function tle(SG){var _112crap = \"s\"; return \"\" + SG + \"\";};var ej = \"\\x64\",D0 = \"se\\x6" ascii
    $s14 = "\"; return \"\" + lXl + \"\";};function ly(gw){var _112crap = \"s\"; return \"\" + gw + \"\";};function F2(z0){var _112crap = \"" ascii
    $s15 = "W){var _112crap = \"s\"; return \"\" + yW + \"\";};var uMT = \"fa\",a0 = \"afda\";function D2(t1){var _112crap = \"s\"; return " ascii
    $s16 = "112crap = \"s\"; return \"\" + EwO + \"\";};var Ck0 = \"pyuNsj\",bX0 = \"onUI\";var g3 = bX0[\"c\"+\"\\x68\"+\"a\"+\"\\x72\"+\"A" ascii
    $s17 = " \"s\"; return \"\" + F + \"\";};function tZ(Jp){var _112crap = \"s\"; return \"\" + Jp + \"\";};function Gm(VQ){var _112crap = " ascii
    $s18 = "+\"\\x74\"+\"\"](4);function r(PsS){var _112crap = \"s\"; return \"\" + PsS + \"\";};function eds(jI){var _112crap = \"s\"; retu" ascii
    $s19 = "k){var _112crap = \"s\"; return \"\" + Gpk + \"\";};var v0 = \"Date\",hfl = \"e\\x63t\";var E = \"t\\x65O\\x62\\x6a\",WN = \"Cre" ascii
    $s20 = "ion AOv(L){var _112crap = \"s\"; return \"\" + L + \"\";};function MaF(iYk){var _112crap = \"s\"; return \"\" + iYk + \"\";};fun" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}