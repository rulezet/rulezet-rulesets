rule sig_20160321_f13e13db85105bf75748017413918951 {
  meta:
    description = "datamaliciousorder - file 20160321_f13e13db85105bf75748017413918951.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00ed094f876dcba0525f17618bd13633f6e0cb0458196546b1bafcc9961a8733"

  strings:
    $s1  = "function Bhxd(S){return S;};function PnTtt(AUr){return AUr;};var MgzO = \"6\\x32\";var u0 = \"\\x383681\";var XrpY = \"21\";func" ascii
    $s2  = "5O\\x62j\";var dX = \"Cre\\x61\";var hHA = function Tub() {return WScript[(function SnjR(){return dX;}()) + (function i(){return" ascii
    $s3  = " + (function cvzww(){return iGJOk;}()) + g(oZPu) + (function Y0(){return aYW;}())]();WScript[h1(AXo) + wbQwD](cHZ());var OqSKZ =" ascii
    $s4  = "()); wzrd = SgKnV(); pcJz = WScript[(function lb(){return dX;}()) + B(rpT) + gNPs(YpLU) + RE(Yu)](wzrd); var uYsM = true; while " ascii
    $s5  = "();while (pcJz[FSJnT(ukb) + (function zG(){return u;}()) + AfC(DIDsa)] < 4 ) {WScript[(function AC(){return AXo;}()) + FBgb(wbQw" ascii
    $s6  = " new this[eim(DdrC)]();var qphve = OqSKZ[tI + xI + O + qfqr(iGJOk) + n(oZPu) + (function Yqa(){return aYW;}())]();WScript[AXo + " ascii
    $s7  = " a){return ILSK - a;};function lO(){return (function CMytI(){return dX;}()) + Za(rpT) + (function x(){return YpLU;}()) + Yu;};fu" ascii
    $s8  = "cHZ() * 1; pBU++){if (rzrR() != 0){Fp = true;alJNJ = true;break;}}function Y() {return Fp && alJNJ;};if (Y()){wKFDP = hHA[V + (f" ascii
    $s9  = "D)](cHZ() * 10)};uYsM = false;} catch(e){};}VuU = WScript[lO()](OJPU(Vy) + UF + Wsha(Y1) + Up(jDKc) + (function ciUs(){return wa" ascii
    $s10 = " UlS = KXUv[\"\\x63harA\\x74\"](1);var fMaWX = \"get\";var CHW = \"Date\";function h1(irPYI){return irPYI;};function U0(gzFNd){r" ascii
    $s11 = "nz(RhwPC) + (function Cxa(){return IeG;}()) + J(R)]((function z(){return ueB;}()) + rCKM(APrl)) + HjKE(JvoDe) + (function wo(){r" ascii
    $s12 = ") + (function og(){return HJNN;}()));}();function lcrr(hYTy){hHA[(function eTMH(){return FYAD;}())](hYTy, 0, 0);};function SgKnV" ascii
    $s13 = "}()) + (function isR(){return YpLU;}()) + (function EF(){return Yu;}())](qJkq(guuC) + Jb + MBp(gT) + (function m(){return JN;}()" ascii
    $s14 = "unction HZA(){return arq;}()) + (function UkM(){return NcpC;}()) + kPv(W) + eZQt + PbE(gjt) + rJL(qgpDf), false);pcJz[na(JvIjV)]" ascii
    $s15 = "(Vtr) + Wm(Ti)] = 0;VuU[kf + PJ(EGrzE) + k0(uMsgT)](wKFDP, 2 );VuU[(function qMFd(){return BB;}()) + weJdf(JTA) + fYVv(o)]();lcr" ascii
    $s16 = "+ aa + B0 + isund(JnbVs) + i0(Psq) + r0 + (function G(){return NDqn;}()) + Q(Wgp) + (function OlDC(){return mreO;}()) + E1(ejl) " ascii
    $s17 = "nction cHZ(){return 22;};function rzrR(){var OqSKZ = new this[h(DdrC)]();var M = OqSKZ[tI + (function iPUFW(){return xI;}()) + O" ascii
    $s18 = "n pBZW(){return xI;}()) + pfk(O) + VfSm(iGJOk) + wro(oZPu) + (function fXVtc(){return aYW;}())]();var Fva = \"QoAHo\";Fva = Kd(q" ascii
    $s19 = "eturn GaB;}()) + PgrIn + (function yZa(){return qMsJr;}()) + (function nSZ(){return HgGht;}()) + (function feRaY(){return eSbc;}" ascii
    $s20 = "(){return FrVH(tH) + ostO(Sxb) + vGd + (function Ey(){return SItfC;}()) + (function hOoW(){return gohrR;}());};function Kd(ILSK," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}