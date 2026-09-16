rule TTP_XOR_QUAD_CurrentVersionRun_d4c6 {
  strings:
    $key_d4c6 = { 87 a9 [2] a3 a7 [2] 88 8b [2] a6 a9 [2] b2 b2 [2] bd a8 [2] a3 b5 [2] a1 b4 [2] ba b2 [2] a6 b5 [2] ba 9a }

  condition:
    any of them
}