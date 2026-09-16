rule TTP_XOR_QUAD_CurrentVersionRun_c8c6 {
  strings:
    $key_c8c6 = { 9b a9 [2] bf a7 [2] 94 8b [2] ba a9 [2] ae b2 [2] a1 a8 [2] bf b5 [2] bd b4 [2] a6 b2 [2] ba b5 [2] a6 9a }

  condition:
    any of them
}