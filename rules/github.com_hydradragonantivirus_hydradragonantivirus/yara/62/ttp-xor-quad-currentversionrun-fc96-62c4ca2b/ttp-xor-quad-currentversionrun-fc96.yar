rule TTP_XOR_QUAD_CurrentVersionRun_fc96 {
  strings:
    $key_fc96 = { af f9 [2] 8b f7 [2] a0 db [2] 8e f9 [2] 9a e2 [2] 95 f8 [2] 8b e5 [2] 89 e4 [2] 92 e2 [2] 8e e5 [2] 92 ca }

  condition:
    any of them
}