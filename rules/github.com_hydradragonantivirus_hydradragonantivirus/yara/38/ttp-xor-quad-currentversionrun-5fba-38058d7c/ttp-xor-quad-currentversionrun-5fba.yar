rule TTP_XOR_QUAD_CurrentVersionRun_5fba {
  strings:
    $key_5fba = { 0c d5 [2] 28 db [2] 03 f7 [2] 2d d5 [2] 39 ce [2] 36 d4 [2] 28 c9 [2] 2a c8 [2] 31 ce [2] 2d c9 [2] 31 e6 }

  condition:
    any of them
}