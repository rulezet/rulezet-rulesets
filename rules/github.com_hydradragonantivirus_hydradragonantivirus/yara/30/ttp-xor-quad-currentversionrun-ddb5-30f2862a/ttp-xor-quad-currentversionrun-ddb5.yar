rule TTP_XOR_QUAD_CurrentVersionRun_ddb5 {
  strings:
    $key_ddb5 = { 8e da [2] aa d4 [2] 81 f8 [2] af da [2] bb c1 [2] b4 db [2] aa c6 [2] a8 c7 [2] b3 c1 [2] af c6 [2] b3 e9 }

  condition:
    any of them
}