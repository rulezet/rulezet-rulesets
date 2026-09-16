rule TTP_XOR_QUAD_CurrentVersionRun_6fba {
  strings:
    $key_6fba = { 3c d5 [2] 18 db [2] 33 f7 [2] 1d d5 [2] 09 ce [2] 06 d4 [2] 18 c9 [2] 1a c8 [2] 01 ce [2] 1d c9 [2] 01 e6 }

  condition:
    any of them
}