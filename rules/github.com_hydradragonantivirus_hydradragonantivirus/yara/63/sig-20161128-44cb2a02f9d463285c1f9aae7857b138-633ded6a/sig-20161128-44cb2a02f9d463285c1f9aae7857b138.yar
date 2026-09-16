rule sig_20161128_44cb2a02f9d463285c1f9aae7857b138 {
  meta:
    description = "datamaliciousorder - file 20161128_44cb2a02f9d463285c1f9aae7857b138.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6248bde2bb89d8bd957ec111e9efafcca992282f7f7a17a4a3bf0b5126c2f4d5"

  strings:
    $s1  = "return new Function(uvhug + ofluny + \"Systemobject')[zame]('C:\\\\\\\\')['type']['length'] > 1\");" fullword ascii
    $s2  = "var ofluny = \"Object('scripting.file\";" fullword ascii
    $s3  = "function myrzyrat() {" fullword ascii
    $s4  = "var erud = null;" fullword ascii
    $s5  = "var rduwabluzfy = true;" fullword ascii
    $s6  = "var efoji = undefined;" fullword ascii
    $s7  = "return kmicjecet;" fullword ascii
    $s8  = "var ecbebysaz = null;" fullword ascii
    $s9  = "if (rduwabluzfy == true) {" fullword ascii
    $s10 = "function lipjibnege() {" fullword ascii
    $s11 = "var jawfedavse = undefined;" fullword ascii
    $s12 = "switch (idjyry()()) {" fullword ascii
    $s13 = "if (mdohkyktaje === null) {" fullword ascii
    $s14 = "function ehduw() {" fullword ascii
    $s15 = "var sfirtuduqla = false;" fullword ascii
    $s16 = "var alhavu = undefined;" fullword ascii
    $s17 = "var slydqyjybt = true;" fullword ascii
    $s18 = "function vsegpunce() {" fullword ascii
    $s19 = "var ujtorvej = null;" fullword ascii
    $s20 = "if (osuzop == dilami.length) break;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}