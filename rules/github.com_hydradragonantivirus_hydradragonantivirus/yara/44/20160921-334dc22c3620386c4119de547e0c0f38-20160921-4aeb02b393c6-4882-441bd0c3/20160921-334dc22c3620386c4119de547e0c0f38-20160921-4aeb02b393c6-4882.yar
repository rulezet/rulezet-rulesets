rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_4aeb02b393c6_4882 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"

  strings:
    $s1 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\"" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s3 = "q\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function" ascii
    $s4 = "unction f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s5 = "n f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"O" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}