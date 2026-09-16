rule TTP_XOR_QUAD_CurrentVersionRun_70a5 {
  strings:
    $key_70a5 = { 23 ca [2] 07 c4 [2] 2c e8 [2] 02 ca [2] 16 d1 [2] 19 cb [2] 07 d6 [2] 05 d7 [2] 1e d1 [2] 02 d6 [2] 1e f9 }

  condition:
    any of them
}