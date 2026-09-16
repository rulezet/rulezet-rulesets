rule TTP_XOR_QUAD_CurrentVersionRun_5ca5 {
  strings:
    $key_5ca5 = { 0f ca [2] 2b c4 [2] 00 e8 [2] 2e ca [2] 3a d1 [2] 35 cb [2] 2b d6 [2] 29 d7 [2] 32 d1 [2] 2e d6 [2] 32 f9 }

  condition:
    any of them
}