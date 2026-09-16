rule sig_20160321_cc56e2791d6d68de18f0f62f970b1b20 {
  meta:
    description = "datamaliciousorder - file 20160321_cc56e2791d6d68de18f0f62f970b1b20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cb5ed3aaa860e18acfef1d7186d4fc5e33720d0a352a60966428c039ca06513"

  strings:
    $s1  = "function s(M1){return M1;};function vuyxU(Tq){return Tq;};function dL(rRKU){return rRKU;};var yO = \"8gtm2q\";var QUFp = \"62\";" ascii
    $s2  = " YnLI;}()) + lb(A) + BJA + e1(lMi); CWsP = F(); XkPcN = WScript[FNFhB + aLl + Ws(w) + vqI + (function z(){return Q;}())](CWsP); " ascii
    $s3  = " + D0 + EK(Uc)]();WScript[(function uK(){return u;}())](Pl());var jnPk = new this[(function yXGe(){return Cq;}()) + (function pJ" ascii
    $s4  = "}()) + WA(D0) + L(Uc)]();WScript[(function ik(){return u;}())](Pl());var jnPk = new this[ahaL(Cq) + fuT]();var y = jnPk[wvsF + b" ascii
    $s5  = " + (function RZtvD(){return MkfXT;}()) + usdEU(DaXa);};function i(ic, R){return ic - R;};function aBZ(){return (function LSENo()" ascii
    $s6  = " = true;mydvl = true;break;}}function Iuha() {return TRM && mydvl;};if (Iuha()){sCRR = kXDT[Q0 + g(iZ) + U + (function MTMQ(){re" ascii
    $s7  = "63\";var w = \"b\\x6a\";var aLl = \"a\\x74eO\";var FNFhB = \"Cr\\x65\";var kXDT = function iNMZt() {return WScript[(function Jfk" ascii
    $s8  = "cript[(function X(){return u;}())](Pl() * 10)};yerr = false;} catch(e){};}gmC = WScript[aBZ()](hjZlB(uxLZ) + SKUNE(NFyO) + (func" ascii
    $s9  = " = VVojY[\"charA\\x74\"](2);function OpeuK(jg){return jg;};var KNw = \"GET\";function IxQ(L1){return L1;};function c(QIVfl){retu" ascii
    $s10 = "var yerr = true; while (yerr){try {XkPcN[UbAJ + IxQ(uI)](OpeuK(KNw), Czrl(aw) + it + (function Dekq(){return NlkH;}()) + nRUvU(C" ascii
    $s11 = " + faAzj + (function WQC(){return oK;}())](XkPcN[oa + aomK + (function WgBEm(){return KO;}()) + Mflp(Fov)]);gmC[EWGXb + WC(Xuq) " ascii
    $s12 = "n FNFhB;}()) + (function sEzVc(){return aLl;}()) + (function YCumo(){return w;}()) + XuGe(vqI) + phpg(Q)]((function lyCCd(){retu" ascii
    $s13 = "){return sbpL;}()) + (function oL(){return Yw;}()) + HvJOo(XuJ) + TEp + (function J(){return laOD;}()) + u0 + Xxg + (function m(" ascii
    $s14 = " DYU);return i(PWdtR, T);}var TRM = false;var mydvl = false;for (var tKgLI = 0; tKgLI < Pl() * 1; tKgLI++){if (ihxFz() != 0){TRM" ascii
    $s15 = "tion e2(){return tMv;}()) + pcEBO + DrhV(N));gmC[(c(UbAJ) + (function bnrA(){return uI;}()))]();gmC[l + QDj] = 1;gmC[bEevu(Iulw)" ascii
    $s16 = "function YPe(){return YtZq;}()) + RJSjz(si) + z0(zDYLB) + e](Mb + pA(Q1) + (function aS(){return LVPTw;}()) + (function etkq(){r" ascii
    $s17 = "+ UuZ : (function Mnz(){return xD;}()) + wf + s(QXu) + vuyxU(Xhd) + dL(QUFp);}" fullword ascii
    $s18 = "(){return fuT;}())]();var DYU = jnPk[Y0(wvsF) + Ex(VR) + (function dADaa(){return Gqbu;}()) + i0(O) + (function K(){return xfVo;" ascii
    $s19 = "eturn xCVRx;}()) + (function qJ(){return Q2;}())) + (function oE(){return lzX;}()) + gCqP + seJYi(PEok) + (function Iby(){return" ascii
    $s20 = "siV(VR) + Gqbu + O + xfVo + D0 + (function Uuwku(){return Uc;}())]();var PWdtR = \"pj\";PWdtR = i(DYU, F0);var T = \"osQL\";T = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}