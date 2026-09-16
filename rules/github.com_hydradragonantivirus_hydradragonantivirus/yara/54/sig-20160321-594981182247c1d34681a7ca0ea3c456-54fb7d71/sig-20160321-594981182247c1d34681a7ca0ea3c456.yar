rule sig_20160321_594981182247c1d34681a7ca0ea3c456 {
  meta:
    description = "datamaliciousorder - file 20160321_594981182247c1d34681a7ca0ea3c456.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3b0bfca7a474a34d6f77479b37988d97f590e8a69625735c6c7caee561a2c0"

  strings:
    $s1  = "function sTDsD(K){return K;};function qesiO(KX){return KX;};var WVA = \"Ktq2Pw\";var HDkby = \"\\x36\\x32\";var eEFCb = \"81\";v" ascii
    $s2  = "WEk)](d());var D = new this[CMz(r)]();var Bixu = D[v1 + LkqJA(FJ) + G0(vFuz) + (function v2(){return ZBrKG;}())]();WScript[wbh(k" ascii
    $s3  = "ile (X[p0(k0) + (function qijk(){return shldU;}()) + aqYYh(MpwmW) + O] < 4 ) {WScript[(function H0(){return knWWt;}()) + mNz + D" ascii
    $s4  = "){return FJ;}()) + Firw(vFuz) + (function GwNW(){return ZBrKG;}())]();WScript[asYCl(knWWt) + (function fS(){return mNz;}()) + W(" ascii
    $s5  = "WScript[(function LJn(){return EBy;}()) + wUwV(dEa) + NjV + (function cOnQ(){return h;}())](ZUygA); var b = true; while (b){try " ascii
    $s6  = "WScript[(function Inbp(){return EBy;}()) + (function UTDE(){return dEa;}()) + (function Um(){return NjV;}()) + (function HepXQ()" ascii
    $s7  = "pAuG;};function gBy(dh, rvk){return dh - rvk;};function SOVI(){return fAVs(EBy) + DH(dEa) + (function acqkA(){return NjV;}()) + " ascii
    $s8  = "P(WEk)](d() * 10)};b = false;} catch(e){};}Hn = WScript[SOVI()](Gjvw(s) + cAy(dnu) + (function at(){return wulG;}()) + (function" ascii
    $s9  = " \"//w\";var Knbr = \"p:\";var Nd = \"h\\x74\\x74\";var auxa = \"\\x47ET\";function KjP(IJBdb){return IJBdb;};function nx(T0){re" ascii
    $s10 = "urn Et;}()) + (function Zr(){return SCh;}()) + mrPWq(Mrwy) + EEDjt(m) + (function AbaN(){return ZFQB;}()) + (function fbYh(){ret" ascii
    $s11 = "aD(yGA) + (function cNleN(){return qrKiK;}())]();FFunh(TEVF);B = \"\" + lmCyw + (function Ajglo(){return k1;}()) + hRg + HE(H1) " ascii
    $s12 = " UiHQ(){return OH;}()));Hn[(nx(L0))]();Hn[(function S0(){return hHmrd;}())] = 1;Hn[flQOs(ypAbZ) + (function rfzT(){return cYS;}(" ascii
    $s13 = "urn CWDgP;}()) + bkuQ(Zuckp) + Im](JkTF + qpgV) + UM + (function Uz(){return z0;}()) + JeM(HYnV) + G1(Ha); ZUygA = PGQkR(); X = " ascii
    $s14 = "(function tcoqM(){return L1;}()) + fxmq(hBop) + nVkA(RvILM) + CXJ + (function JpN(){return U1;}()) + RvSRG + tkAw ? (function TW" ascii
    $s15 = "{return h;}())](D0(yL) + (function o(){return ik;}()) + Sq(B0) + AjgiE + Po(Ebn) + aHFPV(S));}();function FFunh(SdiSQ){y[(functi" ascii
    $s16 = "nWWt) + mNz + (function qb(){return WEk;}())](d());var D = new this[(function U(){return r;}())]();var JKTve = D[OHOO(v1) + (fun" ascii
    $s17 = "j(h);};function d(){return 22;};function v(){var D = new this[(function SGNt(){return r;}())]();var SfwCr = D[v1 + (function xh(" ascii
    $s18 = "))](X[UB(Zhld) + lHTu + bxe(S1) + zVTDA(GigP)]);Hn[(function kGpst(){return MGYOk;}()) + avWs(psRIu) + aFE(oIX) + Kc(KU)] = 0;Hn" ascii
    $s19 = "ction tzinr(){return pmTIK;}()) + U0(fcG) + (function zydkt(){return x;}()) + ZZf + LfX, false);X[Z(RKt) + Xq(G2) + X0(m0)]();wh" ascii
    $s20 = "ction KZw(){return FJ;}()) + (function JZ(){return vFuz;}()) + kkFU(ZBrKG)]();var B = \"NGFR\";B = gBy(Bixu, SfwCr);var KFhF = " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}