rule TTP_XOR_QUAD_CurrentVersionRun_cd93 {
  strings:
    $key_cd93 = { 9e fc [2] ba f2 [2] 91 de [2] bf fc [2] ab e7 [2] a4 fd [2] ba e0 [2] b8 e1 [2] a3 e7 [2] bf e0 [2] a3 cf }

  condition:
    any of them
}