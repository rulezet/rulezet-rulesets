rule sig_20160321_8293d7182d212b75a6b99fee4def85d7 {
  meta:
    description = "datamaliciousorder - file 20160321_8293d7182d212b75a6b99fee4def85d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16641242a349d2b90dc00b1054f63c168810e4e39a0e3903c359e74e4ed2c0dd"

  strings:
    $s1  = "function NOl(Ic){return Ic;};var AP = \"62\";var XHRL = \"3\\x3681\";var bMids = \"2\\x318\";function Vb(tnH){return tnH;};var J" ascii
    $s2  = "[(function IvVtP(){return bPoxK;}()) + up]();while (RoQa[nIsf(mwEYH) + V0(rQY) + (function zwh(){return t;}())] < 4 ) {WScript[(" ascii
    $s3  = "iWyp(){return vdnP;}()) + uG(ocXV)]();WScript[RvE(iCTB) + UIB(vISaE) + (function WELQ(){return soR;}())](lRG());var eq = new thi" ascii
    $s4  = "s[FFauU + (function CmEX(){return g;}())]();var J = eq[Jyq(khcv) + tJk + mb(Cs) + vEGI + q(vdnP) + CJ(ocXV)]();WScript[(function" ascii
    $s5  = ";}()) + ooDn + GxlQt + tD(sFFVV) + FGi; ClhEb = vr(); RoQa = WScript[(function ui(){return aG;}()) + (function a(){return ROa;}(" ascii
    $s6  = "tion jQW(SPqcf, p){return SPqcf - p;};function Cx(){return TV(aG) + (function YeO(){return ROa;}()) + (function OGI(){return j;}" ascii
    $s7  = " != 0){c = true;aT = true;break;}}function Eu() {return c && aT;};if (Eu()){LkvZm = trG[(function zWIen(){return AjzYe;}()) + (f" ascii
    $s8  = "{return JXn;};var zRP = \"c\\x74\";var j = \"eOb\\x6ae\";var ROa = \"at\";var aG = \"Cre\";var trG = function MrSA() {return WSc" ascii
    $s9  = "function pJTlA(){return iCTB;}()) + mpCun(vISaE) + pnK(soR)](lRG() * 10)};ybq = false;} catch(e){};}aVJp = WScript[Cx()](JEhf(VO" ascii
    $s10 = " e0(){return iCTB;}()) + vISaE + GGog(soR)](lRG());var eq = new this[HIe(FFauU) + xW(g)]();var Cmp = eq[ItDZI(khcv) + fBns(tJk) " ascii
    $s11 = "a = jQW(Cmp, J);return jQW(gqxQf, tnXaa);}var c = false;var aT = false;for (var IUvqr = 0; IUvqr < lRG() * 1; IUvqr++){if (yfp()" ascii
    $s12 = " eq[(function kFHP(){return khcv;}()) + tJk + (function kDZdV(){return Cs;}()) + (function HmIn(){return vEGI;}()) + (function X" ascii
    $s13 = "ion U(){return XTx;}())](nii(GG) + LQiU(uo) + (function eKUHg(){return vPcIa;}()) + p0) + Dd(ccF) + (function QgHbz(){return VCK" ascii
    $s14 = "v(){return bMids;}()) + XHRL + NOl(AP);}" fullword ascii
    $s15 = "epX + Reqiz(Qi), (function PQ(){return q0;}()) + EsZ + eWWD + (function J1(){return IzE;}()) + dDrEE + WQ + N(nbAT), false);RoQa" ascii
    $s16 = "a[zS(aUpYm) + (function oVMZE(){return lu;}()) + yPY(Ykh) + BTTT(Snbmg)]);aVJp[(function UDoRm(){return zzx;}()) + (function TGP" ascii
    $s17 = ") + BWE(b) + ck + NwP(WB));aVJp[(p1(fcLQ) + teOqX(ty))]();aVJp[JMGE(Fnb) + (function qnXOe(){return p2;}())] = 1;aVJp[ZOsym](RoQ" ascii
    $s18 = "(Czhvc) + cE(OtRz) + XMQw(zrvT) + Q(nBis) + (function aEuQN(){return a0;}()) + Kn(vi) + c ? gWk + Vb(U0) + yjknO : (function qeY" ascii
    $s19 = "()) + Zp(zRP);};function lRG(){return 22;};function yfp(){var eq = new this[(function mZiE(){return FFauU;}()) + g]();var uzvM =" ascii
    $s20 = "+ (function DBhL(){return Cs;}()) + vEGI + sO(vdnP) + ZO(ocXV)]();var gqxQf = \"YflT\";gqxQf = jQW(J, uzvM);var tnXaa = \"pyG\";" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}