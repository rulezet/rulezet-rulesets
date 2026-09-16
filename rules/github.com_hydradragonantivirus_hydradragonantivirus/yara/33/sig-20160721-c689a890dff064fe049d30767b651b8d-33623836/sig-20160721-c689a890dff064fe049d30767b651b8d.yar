rule sig_20160721_c689a890dff064fe049d30767b651b8d {
  meta:
    description = "datamaliciousorder - file 20160721_c689a890dff064fe049d30767b651b8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd6c710a00e29ff4ff19dbf19c53d7e63ca6c98d9a5fa63c418df7ff613cf8b2"

  strings:
    $s1  = "var FDz=WScript[Lw(Id4) + Iy(Vm) + Sb4 + Ma]((function NNf3(){return Bf1;}()) + Um9 + Tn6 + GVs + Fm6);" fullword ascii
    $s2  = "    var RJw9 = WScript[WSc(Id4) + Vm + Sb4 + Ma](QWx + Oy(XRi9) + (function Ja1(){return Wg1;}()) + TYe6 + LNh);" fullword ascii
    $s3  = "function FZb6(Um){return Um;};var ILf = \"n\" + \"\";" fullword ascii
    $s4  = "function Ya3(WKi1){return WKi1;};var Wn = \"1\" + \"\";" fullword ascii
    $s5  = "function Cu(MPp){return MPp;};var Fc0 = \"File\" + \"\";" fullword ascii
    $s6  = "function Oy(Po6){return Po6;};var LNh = \"ment\" + \"\";" fullword ascii
    $s7  = "function Sr7(TXd2){return TXd2;};var TNy = \"ta\" + \"\";" fullword ascii
    $s8  = "function Ed(Jt3){return Jt3;};var EUr = \"ct\" + \"\";" fullword ascii
    $s9  = "function QWq1(GYi9){return GYi9;};var Ze6 = \"ream\" + \"\";" fullword ascii
    $s10 = "function SBp(An1){return An1;};function WSc(At){return At;};function Lw(CEb0){return CEb0;};function Iy(Om8){return Om8;};var Ma" ascii
    $s11 = "function OKh(Vs0){return Vs0;};var LVz = \"e\" + \"\";" fullword ascii
    $s12 = "function Ac(Ui4){return Ui4;};var Cr = \"e\" + \"\";" fullword ascii
    $s13 = "function Wa9(NJx, Qg2)" fullword ascii
    $s14 = "function FLd(WLf0, Qg2) {" fullword ascii
    $s15 = "function SBp(An1){return An1;};function WSc(At){return At;};function Lw(CEb0){return CEb0;};function Iy(Om8){return Om8;};var Ma" ascii
    $s16 = "function Ju(Qy4){return Qy4;};function HWj4(KCa1){return KCa1;};var DMz = \"m\" + \"\";" fullword ascii
    $s17 = "   JXy6[(function Zl(){return Yr;}()) + Ac(Cr)](NJx);" fullword ascii
    $s18 = "    Yw6[Tm + (function Mw1(){return Eg;}())] = CSt[QNu0 + JEt4 + TWz]();" fullword ascii
    $s19 = "   UUv = JXy6[KEl3 + (function KTb4(){return Gd2;}()) + KUd]();" fullword ascii
    $s20 = "   JXy6 = Gx6[Cu(Ku) + Ja + (function Yp(){return Fc0;}())](Qg2, GWs9, true)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}