rule TTP_XOR_QUAD_CurrentVersionRun_1fba {
  strings:
    $key_1fba = { 4c d5 [2] 68 db [2] 43 f7 [2] 6d d5 [2] 79 ce [2] 76 d4 [2] 68 c9 [2] 6a c8 [2] 71 ce [2] 6d c9 [2] 71 e6 }

  condition:
    any of them
}