rule TTP_XOR_QUAD_CurrentVersionRun_c886 {
  strings:
    $key_c886 = { 9b e9 [2] bf e7 [2] 94 cb [2] ba e9 [2] ae f2 [2] a1 e8 [2] bf f5 [2] bd f4 [2] a6 f2 [2] ba f5 [2] a6 da }

  condition:
    any of them
}