rule sig_20161101_82e1fc2d31a7cf0e799a69d76530bfeb {
  meta:
    description = "datamaliciousorder - file 20161101_82e1fc2d31a7cf0e799a69d76530bfeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "975e515bbf8828b103b05039fe86afad7da43b043d3ef547b07dbb72950c0c62"

  strings:
    $s1  = "var vectowexi = null;" fullword ascii
    $s2  = "return itumhowa;" fullword ascii
    $s3  = "return azgivot;" fullword ascii
    $s4  = "return ciwuxy;" fullword ascii
    $s5  = "function alyx() {" fullword ascii
    $s6  = "return nunas;" fullword ascii
    $s7  = "var imvidqedj = undefined;" fullword ascii
    $s8  = "var utiwuvufx = undefined;" fullword ascii
    $s9  = "function dkysuxnal() {" fullword ascii
    $s10 = "function cythisobz() {" fullword ascii
    $s11 = "function ysnuc() {" fullword ascii
    $s12 = "function uvqobxyvu() {" fullword ascii
    $s13 = "return mowitn;" fullword ascii
    $s14 = "function arop() {" fullword ascii
    $s15 = "function oxtulgy() {" fullword ascii
    $s16 = "if (xuqpicja() == null) {" fullword ascii
    $s17 = "function axidelom() {" fullword ascii
    $s18 = "return yxohirkotc;" fullword ascii
    $s19 = "var itumhowa = false;" fullword ascii
    $s20 = "function vzogedna() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}