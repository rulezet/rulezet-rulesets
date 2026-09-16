rule TTP_XOR_QUAD_CurrentVersionRun_0ea5 {
  strings:
    $key_0ea5 = { 5d ca [2] 79 c4 [2] 52 e8 [2] 7c ca [2] 68 d1 [2] 67 cb [2] 79 d6 [2] 7b d7 [2] 60 d1 [2] 7c d6 [2] 60 f9 }

  condition:
    any of them
}