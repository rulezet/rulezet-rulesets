rule sig_20160321_41ef67d7433b3fdf950127c49e53747d {
  meta:
    description = "datamaliciousorder - file 20160321_41ef67d7433b3fdf950127c49e53747d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc056fbbc13692d2634871b8b4a0dfe05089af85dc081abdbfe2b8957866fcf"

  strings:
    $s1  = "\\x74e\";var IhlT = \"Cr\";var Paa = function GtFx() {return WScript[(function QpBZ(){return IhlT;}()) + yr(DId) + (function zyI" ascii
    $s2  = "rn TCqD;}()) + E(Qq)]();WScript[tfPtf](Fluz());var ZiU = new this[FJUS(a0) + I0(VSp) + (function nODa(){return PHf;}()) + Qm(IP)" ascii
    $s3  = "function PNI(L){return L;};var RlAAP = \"62\";var y2 = \"81\";var og = \"21836\";function b1(w0){return w0;};var yk = \"\\x64f\"" ascii
    $s4  = "sob = WScript[YCcsy()]((function bI(){return RBE;}()) + wrMg + Ojx + dJlJ(VrDyI));msob[(K(C0) + (function NGf(){return duH;}()))" ascii
    $s5  = ")) + (function ITA(){return toAL;}()) + zz(TCqD) + Qq]();WScript[(function panq(){return tfPtf;}())](Fluz());var ZiU = new this[" ascii
    $s6  = " (function E1(){return o2;}()) + (function j0(){return M;}()) + (function aBGfo(){return kjD;}()); e = LyYk(); oiV = WScript[IaD" ascii
    $s7  = "return lwG - iZ;};function YCcsy(){return IhlT + (function RZEaq(){return DId;}()) + uCbPv(gjz) + SePK;};function Fluz(){return " ascii
    $s8  = "n p && NY;};if (rD()){yWfPv = Paa[(function yCVhK(){return E0;}()) + PR(xVZH) + TisvW(NQZRJ) + fUqg(dLGv) + (function u(){return" ascii
    $s9  = "();while (oiV[LQt + ODUg(Whbp) + k(AM)] < 4 ) {WScript[(function QQ(){return tfPtf;}())](Fluz() * 10)};o = false;} catch(e){};}m" ascii
    $s10 = "return BxzN;}()) + (function gLD(){return l0;}()) + FV + JI + XqAG(Vpxaj), false);oiV[(function HH(){return MywwX;}()) + W0(C1)]" ascii
    $s11 = "lse;var NY = false;for (var XPxZ = 0; XPxZ < Fluz() * 1; XPxZ++){if (juw() != 0){p = true;NY = true;break;}}function rD() {retur" ascii
    $s12 = " o1;}()) + tNLPE + ghf + WO + CBP(SoWvy)]((function ERBMx(){return QlD;}()) + ehTbB + (function hCV(){return Oo;}())) + l(fyI) +" ascii
    $s13 = ";}())](S, 0, 0);};function LyYk(){return rC + cIMHW + TTCg + ThjH(bkP) + (function XKot(){return szl;}());};function s(lwG, iZ){" ascii
    $s14 = "]();var gGE = ZiU[(function AcDKS(){return G;}()) + Engc(IO) + (function uVy(){return lWGKn;}()) + (function xbFxX(){return j;}(" ascii
    $s15 = ") + c1 + p ? (function GOi(){return QUa;}()) + P + b1(jrPI) + (function Ls(){return yk;}()) : og + y2 + PNI(RlAAP);}" fullword ascii
    $s16 = "]();msob[T + l2(YBl)] = 1;msob[vwuK + QjkAb](oiV[YomD + DTs(W1) + NRvg + (function V0(){return JUH;}())]);msob[(function a2(){re" ascii
    $s17 = "X(IhlT) + (function ee(){return DId;}()) + gjz + (function dmpac(){return SePK;}())](e); var o = true; while (o){try {oiV[C0 + d" ascii
    $s18 = "22;};function juw(){var ZiU = new this[wUH(a0) + VSp + S0(PHf) + (function FJ(){return IP;}())]();var duPBy = ZiU[(function ixpZ" ascii
    $s19 = "uH]((function jGVP(){return ORru;}()), Jkxz(oXty) + nkFx + YRA(AMn) + b + b0 + Ok(oz) + g(yYHd) + zcXq(AtX) + (function cXNAG(){" ascii
    $s20 = "rn TCqD;}()) + mr(Qq)]();var a = \"tyRn\";a = s(gGE, duPBy);var BxGpO = \"uRMhl\";BxGpO = s(WSB, gGE);return s(a, BxGpO);}var p " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}