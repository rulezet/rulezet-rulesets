rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_68d4a1cff7c2_3693 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_68d4a1cff7c2dbc758cf0077184d0d52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "4d2799f014910856c25b225165971fbe59cf99c8eb1db930d774de46f64d76c2"

  strings:
    $s1 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(fun" ascii
    $s2 = "function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){ret" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){ret" ascii
    $s4 = "(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s5 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Um\";})(),(f" ascii
    $s6 = "(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}