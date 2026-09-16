rule sig_20161214_8ffcb000addc7f76c505c633e2c4664e {
  meta:
    description = "datamaliciousorder - file 20161214_8ffcb000addc7f76c505c633e2c4664e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d9a5876f37fdc646b55dd64f8a8d0911547ffecd12e979cb7c6ccda756580d"

  strings:
    $s1  = "var rymefni = \"Policy     bypass    -noprofile    -wi\";" fullword ascii
    $s2  = "function rlogzo() {" fullword ascii
    $s3  = "return comapp;" fullword ascii
    $s4  = "return inaw;" fullword ascii
    $s5  = "return fipqadra;" fullword ascii
    $s6  = "var qulimw = false;" fullword ascii
    $s7  = "return ahluvvi;" fullword ascii
    $s8  = "function ifdugibm() {" fullword ascii
    $s9  = "return ikdyvz;" fullword ascii
    $s10 = "if (sxibax() == null) {" fullword ascii
    $s11 = "if (umilv() === false) {" fullword ascii
    $s12 = "function xsivo() {" fullword ascii
    $s13 = "var olgyvcobyl = undefined;" fullword ascii
    $s14 = "function opyli() {" fullword ascii
    $s15 = "return fsuxen;" fullword ascii
    $s16 = "var ybvajyr = null;" fullword ascii
    $s17 = "function bryvapi() {" fullword ascii
    $s18 = "if (iqubo() === true) {" fullword ascii
    $s19 = "return sefyvy;" fullword ascii
    $s20 = "function ukforw() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}