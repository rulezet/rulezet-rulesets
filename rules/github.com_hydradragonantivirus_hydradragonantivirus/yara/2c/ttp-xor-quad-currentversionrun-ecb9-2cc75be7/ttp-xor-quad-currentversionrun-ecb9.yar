rule TTP_XOR_QUAD_CurrentVersionRun_ecb9 {
  strings:
    $key_ecb9 = { bf d6 [2] 9b d8 [2] b0 f4 [2] 9e d6 [2] 8a cd [2] 85 d7 [2] 9b ca [2] 99 cb [2] 82 cd [2] 9e ca [2] 82 e5 }

  condition:
    any of them
}