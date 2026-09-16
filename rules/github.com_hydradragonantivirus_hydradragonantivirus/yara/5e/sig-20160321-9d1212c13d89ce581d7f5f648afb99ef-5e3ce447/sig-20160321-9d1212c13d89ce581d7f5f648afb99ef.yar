rule sig_20160321_9d1212c13d89ce581d7f5f648afb99ef {
  meta:
    description = "datamaliciousorder - file 20160321_9d1212c13d89ce581d7f5f648afb99ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8553b19e8f31837833cf8816f3f9f6b5f6c256b65f2530bf27d7472a7a46aad"

  strings:
    $s1  = "function NjLnW(vBS){return vBS;};var o0 = \"\\x38162\";var AHYN = \"\\x3836\";var P1 = \"\\x321\";function v(LDK){return LDK;};v" ascii
    $s2  = "ion PS(){return RyM;}()); B = nJgo(); wYvAb = WScript[(function sXQ(){return cENVV;}()) + Io(OOjH) + (function ubAk(){return vNU" ascii
    $s3  = "(JB) + (function VDv(){return HX;}()) + H + (function C(){return YvI;}());};function l(YuR, GCyE){return YuR - GCyE;};function Y" ascii
    $s4  = "= 0; pkzmz < O() * 1; pkzmz++){if (n() != 0){pOlz = true;e = true;break;}}function ciBQz() {return pOlz && e;};if (ciBQz()){DTUR" ascii
    $s5  = " XHJ + DGb(BJ) + (function QN(){return TZTN;}()) + (function sCnfx(){return CmKEw;}())]();WScript[(function NxT(){return Cai;}()" ascii
    $s6  = " (function yL(){return AfEzb;}()) + (function FAM(){return bKoUF;}())] < 4 ) {WScript[(function XmFD(){return Cai;}())](O() * 10" ascii
    $s7  = ")};tEwY = false;} catch(e){};}XwMV = WScript[Y()](IqpO(q0) + zGm(XjGm) + (function nD(){return seiUV;}()) + TbCI(LnmUJ));XwMV[(S" ascii
    $s8  = "))]();WScript[(function DmrQ(){return Cai;}())](O());var Up = new this[rwz + qXRu]();var mz = Up[l0(WlYB) + SzXOD(x) + s(kTjT) +" ascii
    $s9  = ";};var vNU = \"bj\\x65c\\x74\";var OOjH = \"eO\";var cENVV = \"\\x43\\x72e\\x61t\";var oBQw = function sPu() {return WScript[(fu" ascii
    $s10 = "turn 22;};function n(){var Up = new this[(function xQu(){return rwz;}()) + (function HfSrQ(){return qXRu;}())]();var AWiGR = Up[" ascii
    $s11 = "WlYB + lNXiy(x) + kTjT + XHJ + (function OnU(){return BJ;}()) + (function wh(){return TZTN;}()) + (function Yj(){return CmKEw;}(" ascii
    $s12 = "+ xvd + (function clNc(){return Jm;}()) + BGB]);XwMV[(function NWFJ(){return LunWw;}()) + dAXE(fO) + DW(jreX)] = 0;XwMV[Psu + WH" ascii
    $s13 = "+ (function BPv(){return mib;}()) + E + OPCfN + STWX(sff) + bqFM(DR) + Zyv + Orw + MjPBD + pOlz ? (function n0(){return oIeFT;}(" ascii
    $s14 = "function qQe(){return UBq;}()) + WkZcx(IMSC)](mKxr(oLqQb) + H0(u) + (function ZxoYj(){return h0;}())) + Tny + jNGl + P0 + (funct" ascii
    $s15 = "UfA(Ep) + S)]();XwMV[jdtUR(gti) + rpGuI(dnbN)] = 1;XwMV[PNl(ystDO) + a1 + MUHdg(QW)](wYvAb[(function Abnrj(){return wX;}()) + p " ascii
    $s16 = ")](O());var Up = new this[(function T(){return rwz;}()) + (function P(){return qXRu;}())]();var XwOy = Up[(function R(){return W" ascii
    $s17 = " = oBQw[(function PcfX(){return JD;}()) + (function O0(){return ppw;}()) + JksiL + (function YqNVF(){return xvw;}()) + B0(U) + (" ascii
    $s18 = " NBvl(){return u0;}()) + Sx + (function nhp(){return LTqcP;}()) + pDt + (function o(){return qoiR;}()) + (function Ib(){return p" ascii
    $s19 = ")) + v(mg) + (function GmEo(){return HCnf;}()) : (function M(){return P1;}()) + NjLnW(AHYN) + (function E0(){return o0;}());}" fullword ascii
    $s20 = "return cENVV;}()) + Pqx(OOjH) + q(vNU)](F(A) + EyZ + gw(aDV) + kqZD(SFhf) + (function d(){return a0;}()));}();function puv(NxAn)" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}