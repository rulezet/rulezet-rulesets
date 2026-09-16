rule TTP_XOR_QUAD_CurrentVersionRun_fcba {
  strings:
    $key_fcba = { af d5 [2] 8b db [2] a0 f7 [2] 8e d5 [2] 9a ce [2] 95 d4 [2] 8b c9 [2] 89 c8 [2] 92 ce [2] 8e c9 [2] 92 e6 }

  condition:
    any of them
}