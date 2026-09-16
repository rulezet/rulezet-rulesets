rule sig_20160516_f6eac70fc13d8166d20dd0ced68cc057 {
  meta:
    description = "datamaliciousorder - file 20160516_f6eac70fc13d8166d20dd0ced68cc057.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc42125178d938e8c4bf17b07033e2049c8077068b44367cc8d8d5165f2d5d0"

  strings:
    $s1  = "while (QObZ < MmZP - (6608 + 1412 - 8018)) {" fullword ascii
    $s2  = "function KeygMQ() {" fullword ascii
    $s3  = "function Bcf() {" fullword ascii
    $s4  = "function ZdzsT() {" fullword ascii
    $s5  = "function xpnFENu() {" fullword ascii
    $s6  = "function vzCuux(HxgTuun) {" fullword ascii
    $s7  = "function kvgb() {" fullword ascii
    $s8  = "function SCBDGZK() {" fullword ascii
    $s9  = "function yqre() {" fullword ascii
    $s10 = "return QFCnrH;" fullword ascii
    $s11 = "return wSMwk;" fullword ascii
    $s12 = "return QdVc;" fullword ascii
    $s13 = "function QEx() {" fullword ascii
    $s14 = "return gfjikdi;" fullword ascii
    $s15 = "return ZDhii;" fullword ascii
    $s16 = "return oDiBzI;" fullword ascii
    $s17 = "return muzBoJe;" fullword ascii
    $s18 = "function bZDItIy(tuiyo, fmmd, kemn) {" fullword ascii
    $s19 = "return qBUfOZ;" fullword ascii
    $s20 = "function QxGRgPE() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}