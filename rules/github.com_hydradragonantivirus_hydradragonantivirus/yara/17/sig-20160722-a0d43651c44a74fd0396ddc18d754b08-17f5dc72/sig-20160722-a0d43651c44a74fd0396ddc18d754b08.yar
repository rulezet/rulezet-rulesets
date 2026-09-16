rule sig_20160722_a0d43651c44a74fd0396ddc18d754b08 {
  meta:
    description = "datamaliciousorder - file 20160722_a0d43651c44a74fd0396ddc18d754b08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec0b946d4264a2826da4b07b79e2b28a5282f39cd1b2fc17d120d3cdf9eff5e"

  strings:
    $s1  = "    var UGd7 = WScript[Zl5 + Qb4 + Rr2](Zk4 + Oz1 + Kg0 + Up + (function VXz(){return Sg;}()) + (function Wd8(){return IWo;}()) " ascii
    $s2  = "    var UGd7 = WScript[Zl5 + Qb4 + Rr2](Zk4 + Oz1 + Kg0 + Up + (function VXz(){return Sg;}()) + (function Wd8(){return IWo;}()) " ascii
    $s3  = "    var Xu6 = WScript[Zl5 + Qb4 + (function Ka1(){return Rr2;}())]((function Zm(){return KTy9;}()) + Yi8 + Qj4 + Lg0 + CNp);" fullword ascii
    $s4  = "Sz[(function Yu(){return OQk;}()) + Xi](Pf2 + ZTf);" fullword ascii
    $s5  = "function Aq9(Vy0){return Vy0;};function RBd(EDg4){return EDg4;};var Ij2 = \"nbK\" + \"\";" fullword ascii
    $s6  = "function BVm(YYu){return YYu;};function JFu4(JIo){return JIo;};var Lb = \"nt\" + \"\";" fullword ascii
    $s7  = "function Oe(PUe){return PUe;};var ABz3 = \"ream\" + \"\";" fullword ascii
    $s8  = "function LBt(Og3){return Og3;};var Jb5 = \"alue\" + \"\";" fullword ascii
    $s9  = "function XPz(RNf3){return RNf3;};var Md6 = \"e\" + \"\";" fullword ascii
    $s10 = "var DPa7=Rj + (function FMs(){return Zp;}()) + Aq9(Ue6) + RBd(TXi7) + (function Ye(){return Ij2;}());" fullword ascii
    $s11 = "function RNp2(Rq9){return Rq9;};var Rr2 = \"ject\" + \"\";" fullword ascii
    $s12 = "function Qi6(Wo){return Wo;};function RDh(XOy){return XOy;};function KJu(Dc1){return Dc1;};var DNh3 = \"ct\" + \"\";" fullword ascii
    $s13 = "    IXj0[(function Oo(){return PEj8;}()) + IIg3 + Yd3] = \"bin.base64\";" fullword ascii
    $s14 = "function Wy2(Xl, No)" fullword ascii
    $s15 = "function Wc0(IPc, No) {" fullword ascii
    $s16 = "   UTl2 = XRy7[GBh9 + FVz + KWh9 + Uy7 + Bf0 + (function Ir3(){return Md6;}())](No, Jc7, true)" fullword ascii
    $s17 = "   XRy7 = new ActiveXObject(Zk4 + Oz1 + Qi6(Kg0) + (function Hi(){return Up;}()) + Sg + RDh(IWo) + VGn7 + KJu(DNh3))" fullword ascii
    $s18 = "    var Zs = Vy[Oe(TUb) + (function COv(){return HIq9;}()) + Ff2 + RXz + (function XHn(){return ABz3;}())](Jn, Gi5);" fullword ascii
    $s19 = "   UTl2 = XRy7[GBh9 + FVz + KWh9 + (function Vp9(){return Uy7;}()) + Bf0 + XPz(Md6)](No, Tv);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}