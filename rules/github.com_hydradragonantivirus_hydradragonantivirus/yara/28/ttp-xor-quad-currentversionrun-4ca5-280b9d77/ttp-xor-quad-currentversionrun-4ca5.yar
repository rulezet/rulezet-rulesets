rule TTP_XOR_QUAD_CurrentVersionRun_4ca5 {
  strings:
    $key_4ca5 = { 1f ca [2] 3b c4 [2] 10 e8 [2] 3e ca [2] 2a d1 [2] 25 cb [2] 3b d6 [2] 39 d7 [2] 22 d1 [2] 3e d6 [2] 22 f9 }

  condition:
    any of them
}