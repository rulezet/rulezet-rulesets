rule sig_20160514_ce319c13ea4c04ec81ba9430dfa9c2cc {
  meta:
    description = "datamaliciousorder - file 20160514_ce319c13ea4c04ec81ba9430dfa9c2cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9e9d7a1409f9c665775147b0da0998334012da7d46b0e62fcabc3798bc294b8"

  strings:
    $s1  = "while (rpvvvQie < xtvZLEP - (2958 + 1556 - 4512)) {" fullword ascii
    $s2  = "function gwV(hKH, iKgZLOg) {" fullword ascii
    $s3  = "function JmVIwjv() {" fullword ascii
    $s4  = "VXpl = true;" fullword ascii
    $s5  = "return lJkMl[MRl];" fullword ascii
    $s6  = "function ViW() {" fullword ascii
    $s7  = "return VZpeV;" fullword ascii
    $s8  = "return KMEe;" fullword ascii
    $s9  = "function Mvzhaib() {" fullword ascii
    $s10 = "function Ivqys() {" fullword ascii
    $s11 = "return XNMSA;" fullword ascii
    $s12 = "function AwDlol() {" fullword ascii
    $s13 = "function IoVjsM() {" fullword ascii
    $s14 = "return uiZPBC;" fullword ascii
    $s15 = "function zZMPiZC() {" fullword ascii
    $s16 = "return ICcfNciw;" fullword ascii
    $s17 = "var NCjPvWfj = dAVy(ZGBriQ, epCwaST);" fullword ascii
    $s18 = "function LoI() {" fullword ascii
    $s19 = "function KjUF() {" fullword ascii
    $s20 = "return rFpQjP;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}