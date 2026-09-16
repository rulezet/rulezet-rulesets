rule sig_20160401_d34673e9a2fb161bd8951bc5e3d7bc50 {
  meta:
    description = "datamaliciousorder - file 20160401_d34673e9a2fb161bd8951bc5e3d7bc50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f762909bf65963539928cb2022caea2a797dbfc7ade6bfcda2412e85223c6a12"

  strings:
    $s1  = "ZuIft[EyvWyy](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function AhhAs(LoGr, FyEw){VtcBc = VtcBc * 1; return LoGr - FyEw;};" fullword ascii
    $s3  = "var LdIwb = function XeiSt() {return WScript[AfzFe](\"WScript\"+\".Shell\");}(), BpcHtj = 11;" fullword ascii
    $s4  = "if (ZuIft[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZiDwn() {return LdIwb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NvOJz52JehmH.ex\" + \"e\";};" fullword ascii
    $s6  = "function HhgKjl(){return LuhQkb + \"\";};" fullword ascii
    $s7  = "if (PbkLs && LuXe() && MtrAxe){" fullword ascii
    $s8  = "function LuXe() {return ((PbkLs == true) && (PbkLs == MtrAxe)) ? 1 : VtcBc;};" fullword ascii
    $s9  = "var PbkLs = false;" fullword ascii
    $s10 = "function DjYr(JsgWus) {var BjzKz = (1, 2, 3, 4, 5, JsgWus); return BjzKz;};" fullword ascii
    $s11 = "return AhhAs(DyYrj, DmoHk);" fullword ascii
    $s12 = "var OuYxm = false;" fullword ascii
    $s13 = "function XlEs(MupEv){LdIwb[\"R\"+\"un\"](MupEv, VtcBc, VtcBc);};" fullword ascii
    $s14 = "MtrAxe = true; " fullword ascii
    $s15 = "var MtrAxe = false;" fullword ascii
    $s16 = "function UeIm()" fullword ascii
    $s17 = "}while (UhjSni);" fullword ascii
    $s18 = "function JptLj(){return 23;};" fullword ascii
    $s19 = "PbkLs = true; " fullword ascii
    $s20 = "function QcXdh(){return AfzFe;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}