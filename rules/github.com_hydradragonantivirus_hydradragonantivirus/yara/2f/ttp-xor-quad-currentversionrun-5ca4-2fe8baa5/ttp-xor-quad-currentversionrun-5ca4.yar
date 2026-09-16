rule TTP_XOR_QUAD_CurrentVersionRun_5ca4 {
  strings:
    $key_5ca4 = { 0f cb [2] 2b c5 [2] 00 e9 [2] 2e cb [2] 3a d0 [2] 35 ca [2] 2b d7 [2] 29 d6 [2] 32 d0 [2] 2e d7 [2] 32 f8 }

  condition:
    any of them
}