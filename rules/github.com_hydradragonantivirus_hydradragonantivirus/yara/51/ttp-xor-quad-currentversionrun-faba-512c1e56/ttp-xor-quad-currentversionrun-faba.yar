rule TTP_XOR_QUAD_CurrentVersionRun_faba {
  strings:
    $key_faba = { a9 d5 [2] 8d db [2] a6 f7 [2] 88 d5 [2] 9c ce [2] 93 d4 [2] 8d c9 [2] 8f c8 [2] 94 ce [2] 88 c9 [2] 94 e6 }

  condition:
    any of them
}