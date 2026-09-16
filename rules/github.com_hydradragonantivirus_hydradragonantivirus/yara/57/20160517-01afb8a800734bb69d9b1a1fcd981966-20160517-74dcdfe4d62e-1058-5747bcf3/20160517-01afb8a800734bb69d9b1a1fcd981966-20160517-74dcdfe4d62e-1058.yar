rule _20160517_01afb8a800734bb69d9b1a1fcd981966_20160517_74dcdfe4d62e_1058 {
  meta:
    description = "datamaliciousorder - from files 20160517_01afb8a800734bb69d9b1a1fcd981966.js, 20160517_74dcdfe4d62e0d684302d457cfd31d49.js, 20160517_8fb8d36a93df6cfe18c3cef52db47603.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69307d1d429dafa1f56c874a7f9d2283275c502e1f1d71b6e3b914f5544a8688"
    hash2       = "191ff4e06b2063fa3d28b7fd105b8133c8b2b625c5bc75aaa4b5cf88effeb777"
    hash3       = "eba86826a36f26121f0178a525feb492d1de7750313999b5c8762db75aa213de"

  strings:
    $s1 = "var nConverts1 /* w  */ = function dumpy() {return detail[enjoy0]((\"fdasfadsfaszxvc\", KUWAIT)+\".Shell\");}(), accumulator0 = " ascii
    $s2 = "dumpy1 /* w  */ = \"start \"+accumulator+\"\\r\\nexit\"" fullword ascii
    $s3 = "function tempstore(){return enjoy0 /* w  */;};" fullword ascii
    $s4 = "var enjoy1 /* w  */ = false;" fullword ascii
    $s5 = "batch =/* w  */ \"R\" + \"esponseB\"/* w  */ + \"ydo\".split('').reverse().join('');" fullword ascii
    $s6 = "could = /* w  */(/* w  */\"noitisop\").split(''/* w  */).reverse(/* w  */).join('');" fullword ascii
    $s7 = "enjoy1 /* w  */ /* w  */= true;/* w  */" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}