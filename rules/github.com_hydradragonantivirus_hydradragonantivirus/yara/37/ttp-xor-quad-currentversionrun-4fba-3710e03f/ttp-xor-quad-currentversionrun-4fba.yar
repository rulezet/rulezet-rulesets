rule TTP_XOR_QUAD_CurrentVersionRun_4fba {
  strings:
    $key_4fba = { 1c d5 [2] 38 db [2] 13 f7 [2] 3d d5 [2] 29 ce [2] 26 d4 [2] 38 c9 [2] 3a c8 [2] 21 ce [2] 3d c9 [2] 21 e6 }

  condition:
    any of them
}