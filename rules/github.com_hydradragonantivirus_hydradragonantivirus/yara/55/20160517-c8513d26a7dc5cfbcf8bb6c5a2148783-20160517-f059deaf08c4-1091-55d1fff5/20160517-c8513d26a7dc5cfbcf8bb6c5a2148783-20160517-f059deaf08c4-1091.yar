rule _20160517_c8513d26a7dc5cfbcf8bb6c5a2148783_20160517_f059deaf08c4_1091 {
  meta:
    description = "datamaliciousorder - from files 20160517_c8513d26a7dc5cfbcf8bb6c5a2148783.js, 20160517_f059deaf08c44f52f57c55f60a3a1678.js, 20160517_fcd65a7073409949ad003dade4b7d4f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76e85c5e1bb12e52e3c9749588f13e22d743938973d3125d8cd264941b114826"
    hash2       = "86ceacf5b79d94f5ff6012fdee0be100da2bfb3c9582461e0a7594eb26fefbee"
    hash3       = "533067e382278b5b2f2ea56920ea666e0821e3f076ac9bdc3022e2c61169b53c"

  strings:
    $s1 = "var nConverts1 /* M  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* M  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* M  */;};" fullword ascii
    $s4 = "var enjoy1 /* M  */ = false;" fullword ascii
    $s5 = "could = /* M  */(/* M  */\"noitisop\").split(''/* M  */).reverse(/* M  */).join('');" fullword ascii
    $s6 = "enjoy1 /* M  */ /* M  */= true;/* M  */" fullword ascii
    $s7 = "batch =/* M  */ \"R\" + \"esponseB\"/* M  */ + \"ydo\".split('').reverse().join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}