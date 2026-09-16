rule sig_20160321_f6bd58ff80868ea6cc775924fd97601e {
  meta:
    description = "datamaliciousorder - file 20160321_f6bd58ff80868ea6cc775924fd97601e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "911599d9c2d86b409c1961872542ece2e909ec041e1cffae9ab328d198c1d5b0"

  strings:
    $s1  = "function vekkC(){return rL;}()) + br(V) + vRj(wXE)]();WScript[tVMrQ + JeoP(gZr) + (function BmW(){return tPC;}())](XgJ());var Cu" ascii
    $s2  = "(function xyBy(){return rL;}()) + nFw(V) + (function XPD(){return wXE;}())]();WScript[(function xqMXI(){return tVMrQ;}()) + (fun" ascii
    $s3  = "urn NK;}()) + fL(LO) + (function KhxRZ(){return eKcj;}()); LW = M(); fiQe = WScript[daI(F) + (function FuJbR(){return DE;}()) + " ascii
    $s4  = "var e1 = \"62\";var vrsFb = \"681\";var i1 = \"\\x32183\";var J1 = \"df\";var rNfpO = \"as\";var aO0 = \"asdf\";function x0(Zu){" ascii
    $s5  = "WScript[j()](bG(Eh) + (function i0(){return Zl;}()) + iEe(xY) + HSxK);g[(SUVzd(lKZc))]();g[(function N(){return ZVr;}()) + gmLXx" ascii
    $s6  = "XL;}()) + qJ;};function YAET(h, Zihy){return h - Zihy;};function j(){return (function NyW(){return F;}()) + DE + ViVHH + oIw(CB)" ascii
    $s7  = ";var p = false;for (var B = 0; B < XgJ() * 1; B++){if (E() != 0){NL = true;p = true;break;}}function Tf() {return NL && p;};if (" ascii
    $s8  = "eturn EN;}())] < 4 ) {WScript[rgzd(tVMrQ) + (function gUp(){return gZr;}()) + tPC](XgJ() * 10)};ZvtSg = false;} catch(e){};}g = " ascii
    $s9  = " CB = \"c\";var ViVHH = \"\\x4f\\x62je\";var DE = \"ate\";var F = \"\\x43re\";var I = function TxO() {return WScript[(function B" ascii
    $s10 = "F;}()) + (function XJRt(){return DE;}()) + ry(ViVHH) + (function Job(){return CB;}()) + Ket](b0 + x + EPBi + wZbl(NLBb));}();fun" ascii
    $s11 = "+ (function FpG(){return YDSB;}())]();r(hGmJB);LmP = \"\" + x0(nH) + (function zA(){return hAOO;}()) + dV(amQVl) + Qgxkx(HdxDY) " ascii
    $s12 = "(function MdpG(){return DD;}()) + kB + bTRG(pEnMj) + SBgAp + mBM + y2 + (function zZcb(){return VFPB;}()) + (function dvXks(){re" ascii
    $s13 = "(fUxMD)] = 1;g[(function ZCNvf(){return BhHX;}()) + bkjF + g2](fiQe[RD + (function neBXo(){return R0;}()) + czqZ + MCLb(eExd) + " ascii
    $s14 = "Tf()){hGmJB = I[(function fu0(){return D0;}()) + A0 + HbKPE(gGcFW) + aaGCt(sb) + J0(f) + Dv(Ers) + (function e0(){return B1;}())" ascii
    $s15 = "){return pOP;}()) + wnaw(niD) + BROaR(uN) + PUrgs + PHfaW(B2) + XU(lzX) + gy(jtkJ) + X + g1 + MmEI + (function ujUV(){return gc;" ascii
    $s16 = "urn V;}()) + wXE]();var LmP = \"grXF\";LmP = YAET(auS, D);var VH = \"wcW\";VH = YAET(JyWC, auS);return YAET(LmP, VH);}var NL = f" ascii
    $s17 = "]();var auS = Cuz[(function z(){return O;}()) + eAktn(fu) + (function TbN(){return Hhsb;}()) + (function nA(){return gY;}()) + (" ascii
    $s18 = "turn bB;}()) + Bd + (function zyU(){return oycIZ;}()) + JVm(keNb) + NL ? (function wg(){return aO0;}()) + (function LyEp(){retur" ascii
    $s19 = "z = new this[(function DfWF(){return Nu;}()) + NVho]();var JyWC = Cuz[O + fu + Hhsb + ajz(gY) + BcqH(rL) + (function UWBDk(){ret" ascii
    $s20 = "ction Zyz(){return gZr;}()) + J(tPC)](XgJ());var Cuz = new this[(function CWJU(){return Nu;}()) + (function s(){return NVho;}())" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}