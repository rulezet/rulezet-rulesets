rule TTP_XOR_QUAD_CurrentVersionRun_d8b4 {
  strings:
    $key_d8b4 = { 8b db [2] af d5 [2] 84 f9 [2] aa db [2] be c0 [2] b1 da [2] af c7 [2] ad c6 [2] b6 c0 [2] aa c7 [2] b6 e8 }

  condition:
    any of them
}