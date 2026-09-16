rule sig_20160721_07d4465e81963129c3f2ce27d237b7bf {
  meta:
    description = "datamaliciousorder - file 20160721_07d4465e81963129c3f2ce27d237b7bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87a0c677915dad6421654137d8eaa605eb87e74c2861292cacce0a9bb412ec15"

  strings:
    $s1  = "var Zz=WScript[Yg + AXc4 + BBh + UDu](KWn + Ac + Ai + Tw + (function YQc0(){return Fp;}()));" fullword ascii
    $s2  = "    var Im5 = WScript[Yg + AXc4 + BBh + (function VAb4(){return UDu;}())](Wl + Ss + Hp9 + (function YAq8(){return KPe;}()) + XVb" ascii
    $s3  = "    var IYn = WScript[Yg + AXc4 + BBh + UDu](LKa4(Ks) + (function Jp(){return LNo6;}()) + (function GJj(){return RPd;}()) + Vu2)" ascii
    $s4  = "    var IYn = WScript[Yg + AXc4 + BBh + UDu](LKa4(Ks) + (function Jp(){return LNo6;}()) + (function GJj(){return RPd;}()) + Vu2)" ascii
    $s5  = "    var Im5 = WScript[Yg + AXc4 + BBh + (function VAb4(){return UDu;}())](Wl + Ss + Hp9 + (function YAq8(){return KPe;}()) + XVb" ascii
    $s6  = "function OJi(Up7){return Up7;};var RTo = \"t\" + \"\";" fullword ascii
    $s7  = "function Hl(ZVr4){return ZVr4;};var Ie = \"Write\" + \"\";" fullword ascii
    $s8  = "function Fv2(Ec5){return Ec5;};var ZVh8 = \"21\" + \"\";" fullword ascii
    $s9  = "function HHu(Ew6){return Ew6;};var Nl = \"ose\" + \"\";" fullword ascii
    $s10 = "function Gz4(Ax7){return Ax7;};function JHn(EJz6){return EJz6;};var Ep3 = \"ta\" + \"\";" fullword ascii
    $s11 = "function Jo7(Ua){return Ua;};var DKi = \"t\" + \"\";" fullword ascii
    $s12 = "function LKa4(RIz){return RIz;};var Vu2 = \"ument\" + \"\";" fullword ascii
    $s13 = "function KYf(Cx){return Cx;};var HWg = \"le\" + \"\";" fullword ascii
    $s14 = "var CIg6=Zz.ExpandEnvironmentStrings(Ax0 + (function Rj5(){return Ss0;}()));" fullword ascii
    $s15 = "function UXj(Po){return Po;};var TCc = \"e\" + \"\";" fullword ascii
    $s16 = "function Ko(Ss9, Qs1)" fullword ascii
    $s17 = "function BDs(Uw0, Qs1) {" fullword ascii
    $s18 = "    var YBh7 = Im5[BDo4 + (function KGy5(){return Rd3;}()) + MAj](Uw0);" fullword ascii
    $s19 = "   UTv[(function Kd6(){return Zv7;}()) + Nl]();" fullword ascii
    $s20 = "   UTv = Vw1[(function LPa2(){return Kn4;}()) + VDp + KYf(MTa) + (function UNz(){return Qe4;}()) + HWg](Qs1, Qa, true)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}