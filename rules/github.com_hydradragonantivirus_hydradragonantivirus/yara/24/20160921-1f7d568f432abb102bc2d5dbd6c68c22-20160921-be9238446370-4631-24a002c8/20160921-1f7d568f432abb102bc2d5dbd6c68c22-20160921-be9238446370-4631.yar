rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_be9238446370_4631 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_be923844637026740bc9e5a4aad21ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"

  strings:
    $s1 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s2 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(" ascii
    $s3 = "return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})" ascii
    $s4 = "unction f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s5 = "){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}