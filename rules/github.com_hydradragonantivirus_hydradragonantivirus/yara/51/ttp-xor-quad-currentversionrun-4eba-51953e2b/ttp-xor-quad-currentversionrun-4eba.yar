rule TTP_XOR_QUAD_CurrentVersionRun_4eba {
  strings:
    $key_4eba = { 1d d5 [2] 39 db [2] 12 f7 [2] 3c d5 [2] 28 ce [2] 27 d4 [2] 39 c9 [2] 3b c8 [2] 20 ce [2] 3c c9 [2] 20 e6 }

  condition:
    any of them
}