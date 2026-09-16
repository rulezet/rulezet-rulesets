rule TTP_XOR_QUAD_CurrentVersionRun_fb86 {
  strings:
    $key_fb86 = { a8 e9 [2] 8c e7 [2] a7 cb [2] 89 e9 [2] 9d f2 [2] 92 e8 [2] 8c f5 [2] 8e f4 [2] 95 f2 [2] 89 f5 [2] 95 da }

  condition:
    any of them
}