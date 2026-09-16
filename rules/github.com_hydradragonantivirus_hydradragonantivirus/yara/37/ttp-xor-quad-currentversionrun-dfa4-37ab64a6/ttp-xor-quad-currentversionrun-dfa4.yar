rule TTP_XOR_QUAD_CurrentVersionRun_dfa4 {
  strings:
    $key_dfa4 = { 8c cb [2] a8 c5 [2] 83 e9 [2] ad cb [2] b9 d0 [2] b6 ca [2] a8 d7 [2] aa d6 [2] b1 d0 [2] ad d7 [2] b1 f8 }

  condition:
    any of them
}