rule sig_20160323_1e0bcf5f0c7dea303fb4ac838e903398 {
  meta:
    description = "datamaliciousorder - file 20160323_1e0bcf5f0c7dea303fb4ac838e903398.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5e61a216deda5d27dc7f00d8d3017741ac7da95947b2e8606b92f8d8d1b431c"

  strings:
    $s1  = "function ONb(u2){var _112crap = \"s\"; return \"\" + u2 + \"\";};var ZKL = \"\\x63lose\";function fnx(KjI){var _112crap = \"s\";" ascii
    $s2  = "Je());var Hn = new this[fPO + tK(siT) + xx(Qp)](),Anc = Hn[VtW(q0) + W(jFM) + Tpr(mx) + bND + i0(P) + fgU(seO)]();WScript[hp + H" ascii
    $s3  = " sb + \"\";};var y = \"t\",cS = \"\\x4f\\x62jec\";var tC = \"a\\x74\\x65\",BGI = \"Cre\";var i = false,yFi = function a() {retur" ascii
    $s4  = "c) + h0(F0) + gPy(xVy) + oDV + R(ytZ) + ArT(P0);}; PJ = I(); YY = WScript[uzJ(BGI) + tC + cS + b1(y)](PJ); var Nf = true; while " ascii
    $s5  = " Hn = new this[bQA(fPO) + hO(siT) + Qp](),d = Hn[q0 + jFM + ru(mx) + bND + wo(P) + I1(seO)]();WScript[i1(hp) + Yu(EW) + hOx(h)](" ascii
    $s6  = "= \"l\\x6ci\\x73\",mx = \"Mi\";var jFM = \"UTC\",q0 = \"get\";function bQA(PY){var _112crap = \"s\"; return \"\" + PY + \"\";};f" ascii
    $s7  = "n I(){return RtT(w0) + FQF(B) + jZ + hww;};function DFU(qf, Ys){return qf - Ys;};function JH(){return eg(BGI) + tC + jwY(cS) + y" ascii
    $s8  = "3 * zq + WN; break;}}function sx() {return ((Q == UyH) && (Q == true)) ? true : false;};if (Q && sx() && UyH){function b() {retu" ascii
    $s9  = "alse);YY[zQ]();while (YY[inN(x) + We(Q1)] < 4 ) {WScript[HA(hp) + o(EW) + h](Je() * 10)};Nf = false;} catch(A){Nf = (D + Yj, PUq" ascii
    $s10 = "UX + \"\";};function HTW(f){var _112crap = \"s\"; return \"\" + f + \"\";};function V(Ui){var _112crap = \"s\"; return \"\" + Ui" ascii
    $s11 = "p = \"s\"; return \"\" + A0 + \"\";};function eg(vc){var _112crap = \"s\"; return \"\" + vc + \"\";};function jwY(zNx){var _112c" ascii
    $s12 = " \"\";};function T1(JQx){var _112crap = \"s\"; return \"\" + JQx + \"\";};function l0(Y2){var _112crap = \"s\"; return \"\" + Y2" ascii
    $s13 = "ar _112crap = \"s\"; return \"\" + IzQ + \"\";};function FQF(Vf){var _112crap = \"s\"; return \"\" + Vf + \"\";};var hww = \"TP" ascii
    $s14 = "RuY = \"\\x45T\",lp = \"G\";function or(G){var _112crap = \"s\"; return \"\" + G + \"\";};var Y0 = \"\\x6f\\x70en\",Wz = \"serUt" ascii
    $s15 = "x25\",oe = \"\\x25\\x54\";function E0(mD){var _112crap = \"s\"; return \"\" + mD + \"\";};function pTn(db){var _112crap = \"s\";" ascii
    $s16 = "function ONb(u2){var _112crap = \"s\"; return \"\" + u2 + \"\";};var ZKL = \"\\x63lose\";function fnx(KjI){var _112crap = \"s\";" ascii
    $s17 = " + B1 + \"\";};function PTQ(uS){var _112crap = \"s\"; return \"\" + uS + \"\";};var hHg = \"C9UDtYaos\",Qp = \"\\x65\";var siT =" ascii
    $s18 = "tion kOQ(q3){var _112crap = \"s\"; return \"\" + q3 + \"\";};function U0(vWg){var _112crap = \"s\"; return \"\" + vWg + \"\";};f" ascii
    $s19 = "nction wzr(Qq){var _112crap = \"s\"; return \"\" + Qq + \"\";};function Ybj(M){var _112crap = \"s\"; return \"\" + M + \"\";};va" ascii
    $s20 = " _112crap = \"s\"; return \"\" + IrT + \"\";};function I0(SHd){var _112crap = \"s\"; return \"\" + SHd + \"\";};function wBz(A0)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}