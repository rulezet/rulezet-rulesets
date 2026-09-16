rule TTP_XOR_QUAD_CurrentVersionRun_40a5 {
  strings:
    $key_40a5 = { 13 ca [2] 37 c4 [2] 1c e8 [2] 32 ca [2] 26 d1 [2] 29 cb [2] 37 d6 [2] 35 d7 [2] 2e d1 [2] 32 d6 [2] 2e f9 }

  condition:
    any of them
}