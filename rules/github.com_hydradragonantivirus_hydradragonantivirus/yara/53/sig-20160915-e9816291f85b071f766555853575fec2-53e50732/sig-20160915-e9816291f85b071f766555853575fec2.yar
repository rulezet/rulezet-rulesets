rule sig_20160915_e9816291f85b071f766555853575fec2 {
  meta:
    description = "datamaliciousorder - file 20160915_e9816291f85b071f766555853575fec2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ddaf6cdd0310a0f48f8824b3dc7cc25e0972148989479fd17d3736141d83e8f"

  strings:
    $s1  = "function nuspyx2() {" fullword ascii
    $s2  = "function circu6() {" fullword ascii
    $s3  = "function ebegabk9() {" fullword ascii
    $s4  = "function uwyvygobu2() {" fullword ascii
    $s5  = "function cfiglymnuci1() {" fullword ascii
    $s6  = "return zyhjo6;" fullword ascii
    $s7  = "function mavqu9() {" fullword ascii
    $s8  = "return bgehonitr5;" fullword ascii
    $s9  = "return mgosxec5;" fullword ascii
    $s10 = "function edkowibepj7() {" fullword ascii
    $s11 = "return dasipa7;" fullword ascii
    $s12 = "return bylsi2;" fullword ascii
    $s13 = "return ygexn9;" fullword ascii
    $s14 = "return ugob6;" fullword ascii
    $s15 = "function hucjylo1() {" fullword ascii
    $s16 = "function teklabmommaqk9() {" fullword ascii
    $s17 = "return uxavhagtawhu0;" fullword ascii
    $s18 = "function ktezurtyjywz9() {" fullword ascii
    $s19 = "function raqwetryga3() {" fullword ascii
    $s20 = "return osfaraw5;" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}