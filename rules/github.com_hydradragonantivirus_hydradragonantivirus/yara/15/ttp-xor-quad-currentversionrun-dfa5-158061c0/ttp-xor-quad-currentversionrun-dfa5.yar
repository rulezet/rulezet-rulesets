rule TTP_XOR_QUAD_CurrentVersionRun_dfa5 {
  strings:
    $key_dfa5 = { 8c ca [2] a8 c4 [2] 83 e8 [2] ad ca [2] b9 d1 [2] b6 cb [2] a8 d6 [2] aa d7 [2] b1 d1 [2] ad d6 [2] b1 f9 }

  condition:
    any of them
}