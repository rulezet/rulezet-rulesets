rule sig_20160722_69e3d2b421a2ba2bced1be8e5464ab09 {
  meta:
    description = "datamaliciousorder - file 20160722_69e3d2b421a2ba2bced1be8e5464ab09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481e4e3e0bc3355023784890f61a4da7cd6b6e5007ad34ab599bc8237de503d4"

  strings:
    $s1  = "var Ug=WScript[OWb + Mj + Gl(APi4)]((function EIl(){return KJs;}()) + CXu + QJj0 + Bu4 + Du);" fullword ascii
    $s2  = "    var Hd0 = WScript[(function Um0(){return OWb;}()) + Mj + APi4]((function Qt(){return Qp0;}()) + Bo + Nh + Jn);" fullword ascii
    $s3  = "    var FPh5 = WScript[OWb + Mi1(Mj) + (function SEh9(){return APi4;}())](PVr8 + (function RCn(){return QJz;}()) + DGm9 + (funct" ascii
    $s4  = "    var FPh5 = WScript[OWb + Mi1(Mj) + (function SEh9(){return APi4;}())](PVr8 + (function RCn(){return QJz;}()) + DGm9 + (funct" ascii
    $s5  = "function QOj8(EVe0){return EVe0;};var PRk3 = \"e\" + \"\";" fullword ascii
    $s6  = "function Go(VAd6){return VAd6;};var OXs = \"ile\" + \"\";" fullword ascii
    $s7  = "function LGw6(FHx8){return FHx8;};var Yb1 = \"am\" + \"\";" fullword ascii
    $s8  = "function USr8(Do){return Do;};var Za = \"ll\" + \"\";" fullword ascii
    $s9  = "function VHs(Hn8){return Hn8;};var Wf0 = \".e\" + \"\";" fullword ascii
    $s10 = "ion GDc7(){return Fd;}()) + GBz(Nj) + MDq + Nq + Kl1 + Kf8);" fullword ascii
    $s11 = "var BRz=QEv0 + OMn5 + (function SBe0(){return Bi4;}()) + Nh0 + YIw6;" fullword ascii
    $s12 = "function GBz(SVq){return SVq;};function DWs(Sm6){return Sm6;};function DUk1(NNc){return NNc;};var Kf8 = \"t\" + \"\";" fullword ascii
    $s13 = "function Mi1(UUp){return UUp;};function Wb(Lu1){return Lu1;};function Gl(CFv){return CFv;};var APi4 = \"ect\" + \"\";" fullword ascii
    $s14 = "function BPx(Ax3){return Ax3;};var LCl8 = \"se\" + \"\";" fullword ascii
    $s15 = "function VLu(CAh){return CAh;};var Dh0 = \"Type\" + \"\";" fullword ascii
    $s16 = "function HAj6(Si9, Vi)" fullword ascii
    $s17 = "function MEr7(Uu1, Vi) {" fullword ascii
    $s18 = "   RQx = new ActiveXObject(PVr8 + QJz + DGm9 + Fd + DWs(Nj) + MDq + (function CWd0(){return Nq;}()) + Kl1 + DUk1(Kf8))" fullword ascii
    $s19 = "    CRr0[Xu1 + (function HMd(){return LCl8;}())]();" fullword ascii
    $s20 = "    Bx6[Wy1 + Cx6 + (function VMq5(){return TEg3;}())](Kb6[QCd + (function BJt6(){return Hs9;}()) + Ou + QOj8(PRk3)]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}