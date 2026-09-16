rule sig_20160321_6f103923e53467182fe382dabc67ddc2 {
  meta:
    description = "datamaliciousorder - file 20160321_6f103923e53467182fe382dabc67ddc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "315411e3ad9cc4d9b78cf85886b54e84771cb38eb08d78cb70f125072b66232b"

  strings:
    $s1  = "var NPD = \"162\";var jI = \"8\";var GI = \"21\\x383\\x36\";function rCq(G0){return G0;};function QqvfJ(jp){return jp;};var PbDu" ascii
    $s2  = " C = \"\\x62jec\";var iqVBs = \"eO\";var m0 = \"\\x72e\\x61t\";var fk = \"C\";var lCSR = function JzXbp() {return WScript[Cszw(f" ascii
    $s3  = "[Horei(yXUQ) + Jr(gqvn)]();while (FcNRF[C0 + xhX + ktzfP(ruy)] < 4 ) {WScript[(function c(){return iD;}()) + IWXQH](MQ() * 10)};" ascii
    $s4  = "KLUPu(){return H0;}())]();WScript[iD + VJL(IWXQH)](MQ());var W0 = new this[CDZP]();var SI = W0[(function u0(){return kcW;}()) + " ascii
    $s5  = "smb + nNf + JheB(VY) + jkGlK + H0]();WScript[(function BJs(){return iD;}()) + (function z(){return IWXQH;}())](MQ());var W0 = ne" ascii
    $s6  = "W; kb = Ze(); FcNRF = WScript[fk + (function cE(){return m0;}()) + iqVBs + (function X(){return C;}()) + (function vHPMH(){retur" ascii
    $s7  = "zP) + (function tMb(){return MZTye;}()) + bRk;};function Ziay(e, Mw){return e - Mw;};function rqp(){return big(fk) + m0 + mgl(iq" ascii
    $s8  = "BGEQ(bIN)]);gFWW[XtE(Fs) + (function xV(){return rdcwo;}()) + OILk + bDe(bogI)] = 0;gFWW[(function ZMIa(){return EVWNp;}()) + (f" ascii
    $s9  = "Rr = false;} catch(e){};}gFWW = WScript[rqp()](dvl + SNAxY(G) + (function Bc(){return WNh;}()) + JtR + (function MA(){return Cv;" ascii
    $s10 = "on Gde(){return S;}()) + (function uRsAr(){return lx;}()) + (function cZf(){return nd;}()) + (function K(){return OMgP;}()) + Zv" ascii
    $s11 = "GKNk) + (function A1(){return AEl;}()) + F0 + EY(YCD) + (function hr(){return ARjUB;}()) + (function WGi(){return O0;}()) + FwJS" ascii
    $s12 = "unction kBB(){return KPHAP;}()) + (function ng(){return hu;}())](nbcZ, 2 );gFWW[(function zRrw(){return PtWQc;}())]();Bs(nbcZ);B" ascii
    $s13 = "& DBSt;};if (W()){nbcZ = lCSR[NhY(XEtyW) + nfADc + (function ggM(){return yO;}()) + (function VujL(){return dqkAr;}()) + (functi" ascii
    $s14 = "+ (function Em(){return H0;}())]();var BLK = \"m\";BLK = Ziay(SI, czix);var f = \"o\";f = Ziay(B, SI);return Ziay(BLK, f);}var V" ascii
    $s15 = "LK = \"\" + (function apb(){return Q;}()) + (function L(){return v0;}()) + (function iYk(){return TWp;}()) + (function R0(){retu" ascii
    $s16 = "w this[NHyfo(CDZP)]();var B = W0[(function ki(){return kcW;}()) + (function lje(){return smb;}()) + e0(nNf) + J(VY) + B0(jkGlK) " ascii
    $s17 = "(FU)](Hi(nfKM) + (function rSX(){return KcoI;}()) + (function vpdIW(){return jinw;}()) + (function fLF(){return SWl;}())) + PZI(" ascii
    $s18 = "XXRDp) + BT(sRdLT) + (function rpTnv(){return maRH;}()) + VM ? rCq(U1) + bg + QqvfJ(PbDu) : (function a(){return GI;}()) + (func" ascii
    $s19 = "tion O1(){return jI;}()) + NPD;}" fullword ascii
    $s20 = "s[(function zjdQ(){return CDZP;}())]();var czix = W0[kcW + XOQK(smb) + (function WVn(){return nNf;}()) + VY + jkGlK + (function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}