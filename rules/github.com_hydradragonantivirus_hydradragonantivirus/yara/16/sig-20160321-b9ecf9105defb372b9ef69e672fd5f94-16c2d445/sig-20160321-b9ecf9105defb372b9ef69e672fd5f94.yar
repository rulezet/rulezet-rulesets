rule sig_20160321_b9ecf9105defb372b9ef69e672fd5f94 {
  meta:
    description = "datamaliciousorder - file 20160321_b9ecf9105defb372b9ef69e672fd5f94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9abbcd3fc7a1263cb7d714ac7211e52f151aaf5fef2ee1b20dc8c362cc2e064b"

  strings:
    $s1  = "function vum(LtJw){return LtJw;};function cls(D1){return D1;};var zi = \"\\x3162\";var NH = \"\\x368\";var RkR = \"218\\x33\";fu" ascii
    $s2  = "ion Ety(){return y1;}()) + (function rgf(){return ETk;}()) + ABCR(ENHUt); Uq = NOfT(); opgb = WScript[(function FLE(){return Rpp" ascii
    $s3  = " (function QIEDe(){return PFr;}())]();var XpmOP = gH[fyVv + D + (function dWmE(){return UEuZy;}()) + W(BC)]();WScript[(function " ascii
    $s4  = "mUx;}()) + (function xTc(){return FSt;}()), false);opgb[P(hmSF)]();while (opgb[won(ISmi) + zz + d + GNb(ZXt)] < 4 ) {WScript[xV(" ascii
    $s5  = "+ IwxA(D) + (function okQ(){return UEuZy;}()) + mNfAo(BC)]();WScript[Ss + (function RCJko(){return y0;}())](eeBS());var gH = new" ascii
    $s6  = " ycKtF;};function VTeb(l, A){return l - A;};function KX(){return Rppzp + YGU + (function Uda(){return vGd;}()) + (function deI()" ascii
    $s7  = "drUTW < eeBS() * 1; drUTW++){if (MJGdz() != 0){oopgG = true;NrRK = true;break;}}function yYl() {return oopgG && NrRK;};if (yYl()" ascii
    $s8  = "Ss) + y0](eeBS() * 10)};V = false;} catch(e){};}jGhd = WScript[KX()](Dp(bmsm) + (function WmtR(){return VQV;}()) + (function oxm" ascii
    $s9  = "aBJYe = \"O\\x62\\x6ae\";var vGd = \"\\x61\\x74e\";var YGU = JH[\"charA\\x74\"](2);var Rppzp = \"Cr\";var oSx = function c() {re" ascii
    $s10 = "\"Run\";function eQrVY(B){return B;};function r(g){return g;};var qyPsH = \"ncGdIp\";var jHOD = \"ll\";var I = \"t.She\";var v =" ascii
    $s11 = "secon\";var EgiK = \"l\\x6ci\";var jj = \"getMi\";var F0 = \"te\";var iFEUN = \"Da\";function xV(Lu){return Lu;};var raoV = \"3p" ascii
    $s12 = "{return aBJYe;}()) + (function mD(){return uHV;}());};function eeBS(){return 22;};function MJGdz(){var gH = new this[wB(GgGvp) +" ascii
    $s13 = "ion vE(){return cRNhn;}()) + (function jDp(){return sKyEy;}()) + q0(bD) + M(nTjH)]);jGhd[kz(D0) + Gi + Rgl(q1)] = 0;jGhd[KhlfM +" ascii
    $s14 = "uThXX(){return Ss;}()) + (function Jcvj(){return y0;}())](eeBS());var gH = new this[pdlR(GgGvp) + Sa(PFr)]();var CjgT = gH[fyVv " ascii
    $s15 = "on K0(){return nZQI;}()) + (function mXSc(){return I0;}()) + (function usAS(){return R;}()) + VxFw(xMV) + (function ANxH(){retur" ascii
    $s16 = " (function eC(){return I;}()) + r(jHOD));}();function Gn(vhY){oSx[Ep(xmTxC)](vhY, 0, 0);};function NOfT(){return rxmE + ihA(i) +" ascii
    $s17 = "ion g0(){return LeXn;}()) + MaNVO(OsII) : vum(RkR) + cls(NH) + (function lWYqm(){return zi;}());}" fullword ascii
    $s18 = "bfs(Rppzp) + syWn(YGU) + (function SZ(){return vGd;}()) + aBJYe + LPQ(uHV)](eQrVY(hcz) + (function cxBZ(){return rXkx;}()) + v +" ascii
    $s19 = "ction f0(){return JJZzn;}()))]();jGhd[AsgR(RlfJ) + (function jHzAc(){return yw;}())] = 1;jGhd[SHmI(Ky) + O0 + LA(N)](opgb[(funct" ascii
    $s20 = " tPj(){return qM;}()) + (function Cqk(){return JJZzn;}())](XC(PDSS), (function ciU(){return CWMoM;}()) + (function E1(){return s" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}