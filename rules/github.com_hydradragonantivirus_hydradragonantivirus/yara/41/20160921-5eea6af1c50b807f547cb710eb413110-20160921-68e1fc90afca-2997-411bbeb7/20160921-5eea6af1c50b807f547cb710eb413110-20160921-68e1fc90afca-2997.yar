rule _20160921_5eea6af1c50b807f547cb710eb413110_20160921_68e1fc90afca_2997 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1 = "urn \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s2 = "return \"PTs\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()" ascii
    $s3 = "n \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5 = "return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})()" ascii
    $s6 = "0(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";}" ascii
    $s7 = "urn \"DNa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}