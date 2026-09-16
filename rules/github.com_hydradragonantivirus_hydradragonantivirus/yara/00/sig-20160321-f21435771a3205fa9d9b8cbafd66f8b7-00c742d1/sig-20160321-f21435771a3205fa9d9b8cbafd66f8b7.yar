rule sig_20160321_f21435771a3205fa9d9b8cbafd66f8b7 {
  meta:
    description = "datamaliciousorder - file 20160321_f21435771a3205fa9d9b8cbafd66f8b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0aece794efc6521515271dcb4f80db0ac6190c3f8bb7886f230440ef93cb21"

  strings:
    $s1  = "function L(Qwu){return Qwu;};var g0 = \"X3d8X2\";var T = \"162\";var ACj = \"\\x368\";var iAD = \"183\";var dot = g0[\"\\x63ha" ascii
    $s2  = " HEI]();var QkcXH = KHjIQ[(function HPHa(){return AAfVn;}()) + CGH(mZ) + i + iXGTJ + Y(nHURX)]();WScript[urh + p(SsbRQ)](FuxLU()" ascii
    $s3  = "tion q(){return nHURX;}())]();WScript[(function vqC(){return urh;}()) + NhT(SsbRQ)](FuxLU());var KHjIQ = new this[tsSof(BmKcP) +" ascii
    $s4  = "le (OAmp[(function ji(){return ubtj;}()) + (function nxW(){return qmw;}())] < 4 ) {WScript[OyZQI(urh) + RoU(SsbRQ)](FuxLU() * 10" ascii
    $s5  = "nD = \"C\\x72\\x65a\";var Mgu = function VZm() {return WScript[(function DKECx(){return TygnD;}()) + lraz + (function Qk(){retur" ascii
    $s6  = "nction KK(){return J0;}()) + a + Awz(fW) + (function x0(){return Dz;}()); TehK = P(); OAmp = WScript[LsBA(TygnD) + m(lraz) + yQI" ascii
    $s7  = "){return E;}()) + rAGO(Ul) + WgXC + (function JURl(){return PYHET;}()) + qqq;};function u(PvALD, Ytw){return PvALD - Ytw;};funct" ascii
    $s8  = "ct() != 0){VGx = true;iEE = true;break;}}function PaZfT() {return VGx && iEE;};if (PaZfT()){K = Mgu[OxKG(t) + (function Njw(){re" ascii
    $s9  = ")};H = false;} catch(e){};}ZnEuQ = WScript[ipQ()](kkac(UPUKt) + (function VdpE(){return GzZxG;}()) + yoVJ(XOsg));ZnEuQ[(gkzVj(hr" ascii
    $s10 = " = \"\\x75/\\x66\";var FD = \"as.\\x68\";var RBnJT = \"o\\x6e\\x6fz\";var k = \":/\\x2fdr\";var v0 = \"htt\\x70\";var mSDf = \"G" ascii
    $s11 = "63ha\\x72A\\x74\"](5);var i = \"s\";var mZ = \"ill\\x69\";var AAfVn = \"getM\";function mpXZG(TNm){return TNm;};function tsSof(Q" ascii
    $s12 = "I + XxC](TehK); var H = true; while (H){try {OAmp[(function Q(){return hr;}()) + (function ONf(){return QIj;}())]((function fTmi" ascii
    $s13 = "sFB(yqIUI) + fR] = 0;ZnEuQ[(function fxukN(){return U1;}()) + (function Ien(){return nw;}()) + ydre(v1)](K, 2 );ZnEuQ[(function " ascii
    $s14 = "OkI;}()) + ecuiD);}();function MhXuJ(pGWpb){Mgu[eeBbt(hC) + DK(v)](pGWpb, 0, 0);};function P(){return Msir(yfU) + (function vlR(" ascii
    $s15 = ") + tx(QIj))]();ZnEuQ[(function WgLm(){return BNsP;}()) + (function VNhzN(){return Je;}()) + hq] = 1;ZnEuQ[RkEPn(U0) + (function" ascii
    $s16 = "jViBH(){return Ff;}()) + (function KLt(){return RwB;}())]();MhXuJ(K);Pl = \"\" + (function M(){return wZLC;}()) + plex + E1(xwY)" ascii
    $s17 = "\"JZn\";A = u(kQQ, QkcXH);return u(Pl, A);}var VGx = false;var iEE = false;for (var NCdSm = 0; NCdSm < FuxLU() * 1; NCdSm++){if " ascii
    $s18 = "{return 22;};function yct(){var KHjIQ = new this[mpXZG(BmKcP) + HEI]();var h = KHjIQ[dP(AAfVn) + lb(mZ) + izx(i) + iXGTJ + (func" ascii
    $s19 = "ion ipQ(){return (function rxu(){return TygnD;}()) + XWx(lraz) + pWVdk(yQII) + (function wR(){return XxC;}());};function FuxLU()" ascii
    $s20 = " j(){return FD;}()) + (function IMIs(){return o;}()) + (function Zo(){return FaJ;}()) + Ijp(RwXD), false);OAmp[Zhwdy(oMd)]();whi" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}