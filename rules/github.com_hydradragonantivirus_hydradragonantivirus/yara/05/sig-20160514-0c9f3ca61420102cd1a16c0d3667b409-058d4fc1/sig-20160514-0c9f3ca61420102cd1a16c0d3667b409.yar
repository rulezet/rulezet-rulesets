rule sig_20160514_0c9f3ca61420102cd1a16c0d3667b409 {
  meta:
    description = "datamaliciousorder - file 20160514_0c9f3ca61420102cd1a16c0d3667b409.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0280d455af8b6313f16aeae265acde0eb833f8769656af401b84961521f5f70"

  strings:
    $s1  = "while (QRDD < joNfe - (1132 + 2209 - 3339)) {" fullword ascii
    $s2  = "return XAhNTnWe;" fullword ascii
    $s3  = "return QhEXp;" fullword ascii
    $s4  = "function ANCm() {" fullword ascii
    $s5  = "return aoFu;" fullword ascii
    $s6  = "function Bex() {" fullword ascii
    $s7  = "return djhLR;" fullword ascii
    $s8  = "return HOGE;" fullword ascii
    $s9  = "function JdVik(dfegg) {" fullword ascii
    $s10 = "return zeVTCkZD;" fullword ascii
    $s11 = "function BiskpzI() {" fullword ascii
    $s12 = "function jQdoZm(XKuzPk, HAk) {" fullword ascii
    $s13 = "return SgCpr;" fullword ascii
    $s14 = "return hzYeVRf;" fullword ascii
    $s15 = "return doWjRn;" fullword ascii
    $s16 = "function insRmd() {" fullword ascii
    $s17 = "function pSxXd() {" fullword ascii
    $s18 = "function ecOio(PZtMT) {" fullword ascii
    $s19 = "return grbvZEa;" fullword ascii
    $s20 = "var VgeQ = String;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}