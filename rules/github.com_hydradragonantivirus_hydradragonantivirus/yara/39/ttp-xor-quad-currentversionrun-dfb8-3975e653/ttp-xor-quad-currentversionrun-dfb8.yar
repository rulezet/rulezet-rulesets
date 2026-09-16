rule TTP_XOR_QUAD_CurrentVersionRun_dfb8 {
  strings:
    $key_dfb8 = { 8c d7 [2] a8 d9 [2] 83 f5 [2] ad d7 [2] b9 cc [2] b6 d6 [2] a8 cb [2] aa ca [2] b1 cc [2] ad cb [2] b1 e4 }

  condition:
    any of them
}