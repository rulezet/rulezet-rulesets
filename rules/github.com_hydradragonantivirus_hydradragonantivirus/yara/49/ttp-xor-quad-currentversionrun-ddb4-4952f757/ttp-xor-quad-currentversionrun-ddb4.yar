rule TTP_XOR_QUAD_CurrentVersionRun_ddb4 {
  strings:
    $key_ddb4 = { 8e db [2] aa d5 [2] 81 f9 [2] af db [2] bb c0 [2] b4 da [2] aa c7 [2] a8 c6 [2] b3 c0 [2] af c7 [2] b3 e8 }

  condition:
    any of them
}