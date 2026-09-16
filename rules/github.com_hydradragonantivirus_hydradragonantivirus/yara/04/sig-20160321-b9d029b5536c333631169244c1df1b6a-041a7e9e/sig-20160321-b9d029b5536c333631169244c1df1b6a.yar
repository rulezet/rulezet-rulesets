rule sig_20160321_b9d029b5536c333631169244c1df1b6a {
  meta:
    description = "datamaliciousorder - file 20160321_b9d029b5536c333631169244c1df1b6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e1ed83f945ad45dfaa2370593e5fbb16f143c5fd57883712e5151eabd83c19"

  strings:
    $s1  = "]();while (I[P0(PN) + obWHj + M0 + (function Kc(){return o1;}()) + (function kZ(){return LlMt;}())] < 4 ) {WScript[l + D0(r)](J(" ascii
    $s2  = "var zX = \"62\";var aFq = \"\\x33\\x3681\";var oU = \"\\x32\\x318\";var LXs = \"ddhNZu\";var Hw = \"\\x66as\\x64\\x66\";var wkWi" ascii
    $s3  = ")]();WScript[o(l) + (function LhGO(){return r;}())](J());var VFB = new this[s0 + (function VlD(){return Wm;}()) + (function m0()" ascii
    $s4  = " Dwxj(o0); RrEq = m(); I = WScript[(function tdFY(){return KGG;}()) + (function ZswBu(){return D;}()) + opMG + sqv(UGZHo)](RrEq)" ascii
    $s5  = "rn WScript[gdp(KGG) + A(D) + (function kOx(){return opMG;}()) + Bl(UGZHo)](N + MiDyx + (function lTs(){return eUMcy;}()) + (func" ascii
    $s6  = "function xmv(){return PoC;}()) + (function u(){return Z;}()) + cgiV]();WScript[dG(l) + Xyjwm(r)](J());var VFB = new this[s0 + T(" ascii
    $s7  = "Jcft(){return FFL;}()) + (function kztC(){return C;}()) + ohIc;};function fm(P, MLZU){return P - MLZU;};function cn(){return (fu" ascii
    $s8  = "Tun && kBr;};if (IquAE()){vDT = Cm[(function zu(){return bfkUv;}()) + EbR(nZ) + vEg(kgxHU) + p(WAw) + (function X0(){return MFc;" ascii
    $s9  = ") * 10)};gngO = false;} catch(e){};}dYbl = WScript[cn()](nve(iO) + (function U2(){return I0;}()) + ek + (function r0(){return U1" ascii
    $s10 = ";}()) + (function jv(){return oyZ;}()));dYbl[(siw(xkC) + sPvZ)]();dYbl[P1] = 1;dYbl[(function ynEy(){return ebmSV;}()) + i2 + (f" ascii
    $s11 = "n 22;};function PFiOn(){var VFB = new this[xlIOY(s0) + Wm + yF(BItuB)]();var Qh = VFB[blPtt + (function iZS(){return N0;}()) + (" ascii
    $s12 = "nction S(){return KGG;}()) + (function GTht(){return D;}()) + arc(opMG) + (function CBH(){return UGZHo;}());};function J(){retur" ascii
    $s13 = ") + GPTun ? (function D2(){return B;}()) + wkWi + Hw : oU + (function u0(){return aFq;}()) + (function ddW(){return zX;}());}" fullword ascii
    $s14 = "tion gFCsF(){return SlzzH;}()));}();function UpupN(LNcrm){Cm[Yd(qzbHl)](LNcrm, 0, 0);};function m(){return Itoh(h) + (function I" ascii
    $s15 = "Wm) + E(BItuB)]();var YpQCe = VFB[TmiE(blPtt) + (function XD(){return N0;}()) + i(PoC) + (function Ey(){return Z;}()) + geM(cgiV" ascii
    $s16 = "ion EEzHv(){return heXg;}()) + (function KZkuA(){return t;}()) + (function qVPr(){return mU;}())] = 0;dYbl[(function ey(){return" ascii
    $s17 = "f(){return pT;}()) + Ba(F1) + fFJES(HhtCp) + Vkv(G), false);I[(function iFh(){return vc;}()) + (function hboI(){return hNWr;}())" ascii
    $s18 = "{return BItuB;}())]();var hLLL = VFB[(function asGlI(){return blPtt;}()) + (function Tkk(){return N0;}()) + th(PoC) + riw(Z) + c" ascii
    $s19 = "unction HAst(){return q;}())](I[(function dDpIn(){return A0;}()) + (function ZVfT(){return Hmab;}()) + myt]);dYbl[USjlu + (funct" ascii
    $s20 = " HbfB;}()) + (function zond(){return JXxnx;}()) + (function VADT(){return Jvv;}()) + lzfC(RGeAF) + frnTy + k](vDT, 2 );dYbl[I1 +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}