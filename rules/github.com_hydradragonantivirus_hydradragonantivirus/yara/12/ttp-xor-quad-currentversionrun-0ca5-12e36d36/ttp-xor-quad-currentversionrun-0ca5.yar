rule TTP_XOR_QUAD_CurrentVersionRun_0ca5 {
  strings:
    $key_0ca5 = { 5f ca [2] 7b c4 [2] 50 e8 [2] 7e ca [2] 6a d1 [2] 65 cb [2] 7b d6 [2] 79 d7 [2] 62 d1 [2] 7e d6 [2] 62 f9 }

  condition:
    any of them
}