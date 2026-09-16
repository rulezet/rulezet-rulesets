rule TTP_XOR_QUAD_CurrentVersionRun_3eba {
  strings:
    $key_3eba = { 6d d5 [2] 49 db [2] 62 f7 [2] 4c d5 [2] 58 ce [2] 57 d4 [2] 49 c9 [2] 4b c8 [2] 50 ce [2] 4c c9 [2] 50 e6 }

  condition:
    any of them
}