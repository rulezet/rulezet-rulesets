rule TTP_XOR_QUAD_CurrentVersionRun_dfb6 {
  strings:
    $key_dfb6 = { 8c d9 [2] a8 d7 [2] 83 fb [2] ad d9 [2] b9 c2 [2] b6 d8 [2] a8 c5 [2] aa c4 [2] b1 c2 [2] ad c5 [2] b1 ea }

  condition:
    any of them
}