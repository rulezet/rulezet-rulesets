rule TTP_XOR_QUAD_CurrentVersionRun_d4d7 {
  strings:
    $key_d4d7 = { 87 b8 [2] a3 b6 [2] 88 9a [2] a6 b8 [2] b2 a3 [2] bd b9 [2] a3 a4 [2] a1 a5 [2] ba a3 [2] a6 a4 [2] ba 8b }

  condition:
    any of them
}