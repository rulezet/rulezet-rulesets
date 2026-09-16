rule TTP_XOR_QUAD_CurrentVersionRun_dfa9 {
  strings:
    $key_dfa9 = { 8c c6 [2] a8 c8 [2] 83 e4 [2] ad c6 [2] b9 dd [2] b6 c7 [2] a8 da [2] aa db [2] b1 dd [2] ad da [2] b1 f5 }

  condition:
    any of them
}