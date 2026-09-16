rule TTP_XOR_QUAD_CurrentVersionRun_c887 {
  strings:
    $key_c887 = { 9b e8 [2] bf e6 [2] 94 ca [2] ba e8 [2] ae f3 [2] a1 e9 [2] bf f4 [2] bd f5 [2] a6 f3 [2] ba f4 [2] a6 db }

  condition:
    any of them
}