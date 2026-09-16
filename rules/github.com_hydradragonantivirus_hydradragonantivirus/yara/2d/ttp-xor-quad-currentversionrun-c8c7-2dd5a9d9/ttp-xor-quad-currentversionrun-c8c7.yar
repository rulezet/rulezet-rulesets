rule TTP_XOR_QUAD_CurrentVersionRun_c8c7 {
  strings:
    $key_c8c7 = { 9b a8 [2] bf a6 [2] 94 8a [2] ba a8 [2] ae b3 [2] a1 a9 [2] bf b4 [2] bd b5 [2] a6 b3 [2] ba b4 [2] a6 9b }

  condition:
    any of them
}