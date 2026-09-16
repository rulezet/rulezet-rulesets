rule sig_20160721_f247b0e4dec6a57dbb60073b7b5d3d12 {
  meta:
    description = "datamaliciousorder - file 20160721_f247b0e4dec6a57dbb60073b7b5d3d12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00f3d67cb462fb0091f25a94ff974348ed51a1823fada1e68242d1d1419ee6ef"

  strings:
    $s1  = "var Dk=WScript[Re + Ve8 + OYp7](MZo3 + Iv + Rm + PWe + (function NJm5(){return Yq8;}()));" fullword ascii
    $s2  = "    var RAt0 = WScript[Re + (function Iu5(){return Ve8;}()) + OYp7](ROn + EZk + DMc5 + VAz5 + AKp4(Td));" fullword ascii
    $s3  = "    var DKw1 = WScript[Tq7(Re) + Ve8 + VTc6(OYp7)](Ax + Xb1(YMm7) + So0 + (function GFr8(){return Bk;}()) + (function Kf2(){retu" ascii
    $s4  = "    var DKw1 = WScript[Tq7(Re) + Ve8 + VTc6(OYp7)](Ax + Xb1(YMm7) + So0 + (function GFr8(){return Bk;}()) + (function Kf2(){retu" ascii
    $s5  = "    var NHn = WScript[(function Ky6(){return Re;}()) + Ve8 + GZz(OYp7)](Dz6(YNk8) + Be9(Bf3) + ASb + KLs3(Gn8) + Ju + OPo);" fullword ascii
    $s6  = "function QCg8(Wl2){return Wl2;};function Wh(Hx){return Hx;};function Mz(Bd9){return Bd9;};var HRw4 = \"e\" + \"\";" fullword ascii
    $s7  = "function Xb1(CTr6){return CTr6;};var SHl3 = \"am\" + \"\";" fullword ascii
    $s8  = "function EUf0(RAg){return RAg;};var Xm3 = \"n\" + \"\";" fullword ascii
    $s9  = "function NFs(As6){return As6;};function Hx3(JEu6){return JEu6;};var Gu = \"m\" + \"\";" fullword ascii
    $s10 = "function GZz(YDd4){return YDd4;};function Tq7(Pz){return Pz;};function VTc6(QBe){return QBe;};var OYp7 = \"bject\" + \"\";" fullword ascii
    $s11 = "function AKp4(NWy9){return NWy9;};var Td = \"ment\" + \"\";" fullword ascii
    $s12 = "function Dz6(KWf){return KWf;};function Be9(CCy){return CCy;};function KLs3(Ie){return Ie;};function EUq(Ri3){return Ri3;};var O" ascii
    $s13 = "function PJt0(Kk3){return Kk3;};var NJl2 = \"a\" + \"\";" fullword ascii
    $s14 = "function Dz6(KWf){return KWf;};function Be9(CCy){return CCy;};function KLs3(Ie){return Ie;};function EUq(Ri3){return Ri3;};var O" ascii
    $s15 = "function RXo6(BRw8, QWb6)" fullword ascii
    $s16 = "function VBc(Tn6, QWb6) {" fullword ascii
    $s17 = "   Wt = new ActiveXObject(YNk8 + (function OQn(){return Bf3;}()) + ASb + Gn8 + Ju + EUq(OPo))" fullword ascii
    $s18 = "    var KEt6 = Xb[(function LZq3(){return HVl;}()) + NFs(XSk8) + (function JJq(){return Km;}()) + Hx3(XIs4) + Gu](ZGt7, IYz);" fullword ascii
    $s19 = "    var Qt3 = RAt0[Ba2 + GNm + Gq + CPn0 + (function My1(){return UIt;}())]((function Ru8(){return IJi;}()) + Kv6 + Hs8 + PJt0(Y" ascii
    $s20 = "    DKw1[(function OBi(){return It7;}()) + YIl] = Hh9;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}