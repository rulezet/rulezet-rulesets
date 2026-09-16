rule sig_20160817_4f21953031d12a2cbc7c54d7c6bec4a1 {
  meta:
    description = "datamaliciousorder - file 20160817_4f21953031d12a2cbc7c54d7c6bec4a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "291ac012ab68d990781d4d56ee425adcba611d511b24d9cae614ce5e1f52d42d"

  strings:
    $s1  = "return nibbatsy2[\"ispyhl\"];" fullword ascii
    $s2  = "return wozhu[0];" fullword ascii
    $s3  = "function avkavqa() {" fullword ascii
    $s4  = "return fjoljexgy2[2];" fullword ascii
    $s5  = "return umjoqybi0[\"ozjimt\"];" fullword ascii
    $s6  = "function fybty() {" fullword ascii
    $s7  = "return vuso9[6];" fullword ascii
    $s8  = "function sisexc() {" fullword ascii
    $s9  = "return dmosygarx4[4];" fullword ascii
    $s10 = "function fzepjejet() {" fullword ascii
    $s11 = "return exhuky0[0];" fullword ascii
    $s12 = "function umnari8() {" fullword ascii
    $s13 = "return zewekso[0];" fullword ascii
    $s14 = "return jgahwase1[1];" fullword ascii
    $s15 = "return hakum8[1];" fullword ascii
    $s16 = "function ignewqywmo5() {" fullword ascii
    $s17 = "return omyqawl[\"utygy\"];" fullword ascii
    $s18 = "function ktygtiq() {" fullword ascii
    $s19 = "function ajhofolp() {" fullword ascii
    $s20 = "return sagy5[\"qkyxy\"];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}