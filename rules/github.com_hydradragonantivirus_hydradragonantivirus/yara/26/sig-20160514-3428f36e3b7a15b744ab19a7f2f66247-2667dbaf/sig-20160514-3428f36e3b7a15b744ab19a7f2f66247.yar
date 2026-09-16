rule sig_20160514_3428f36e3b7a15b744ab19a7f2f66247 {
  meta:
    description = "datamaliciousorder - file 20160514_3428f36e3b7a15b744ab19a7f2f66247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e800b25ddf9f937b9b1caed840ca02918f743827e1835a473b32bb11846bd8c"

  strings:
    $s1  = "while (lMfszK < akMG - (8809 + 1163 - 9970)) {" fullword ascii
    $s2  = "return iSWcivf;" fullword ascii
    $s3  = "function VFlOYT() {" fullword ascii
    $s4  = "function HgsD() {" fullword ascii
    $s5  = "return QbGp;" fullword ascii
    $s6  = "function pSVJoyI() {" fullword ascii
    $s7  = "return Kqabl;" fullword ascii
    $s8  = "var BeXD = false;" fullword ascii
    $s9  = "return KjlIZ;" fullword ascii
    $s10 = "function UXIJEe(Etl) {" fullword ascii
    $s11 = "return dEmwUj;" fullword ascii
    $s12 = "return ZlzQQBJ;" fullword ascii
    $s13 = "return Vygp;" fullword ascii
    $s14 = "var ArTtkfL = true;" fullword ascii
    $s15 = "function VDqi(CyXswRrf, kMwSU) {" fullword ascii
    $s16 = "var sQLJ = false;" fullword ascii
    $s17 = "function ouSCt() {" fullword ascii
    $s18 = "return fzmxc[kAtkJy];" fullword ascii
    $s19 = "var OyEE = false;" fullword ascii
    $s20 = "function uvCYBQN() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}