rule TTP_XOR_QUAD_CurrentVersionRun_c8d7 {
  strings:
    $key_c8d7 = { 9b b8 [2] bf b6 [2] 94 9a [2] ba b8 [2] ae a3 [2] a1 b9 [2] bf a4 [2] bd a5 [2] a6 a3 [2] ba a4 [2] a6 8b }

  condition:
    any of them
}