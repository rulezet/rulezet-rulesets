rule TTP_XOR_QUAD_CurrentVersionRun_eca5 {
  strings:
    $key_eca5 = { bf ca [2] 9b c4 [2] b0 e8 [2] 9e ca [2] 8a d1 [2] 85 cb [2] 9b d6 [2] 99 d7 [2] 82 d1 [2] 9e d6 [2] 82 f9 }

  condition:
    any of them
}