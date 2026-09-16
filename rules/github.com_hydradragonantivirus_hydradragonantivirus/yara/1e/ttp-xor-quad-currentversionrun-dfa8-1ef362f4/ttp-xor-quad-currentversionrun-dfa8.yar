rule TTP_XOR_QUAD_CurrentVersionRun_dfa8 {
  strings:
    $key_dfa8 = { 8c c7 [2] a8 c9 [2] 83 e5 [2] ad c7 [2] b9 dc [2] b6 c6 [2] a8 db [2] aa da [2] b1 dc [2] ad db [2] b1 f4 }

  condition:
    any of them
}