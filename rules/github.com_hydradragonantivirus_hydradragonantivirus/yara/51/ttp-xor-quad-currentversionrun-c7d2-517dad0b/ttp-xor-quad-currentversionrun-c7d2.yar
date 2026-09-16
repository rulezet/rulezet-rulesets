rule TTP_XOR_QUAD_CurrentVersionRun_c7d2 {
  strings:
    $key_c7d2 = { 94 bd [2] b0 b3 [2] 9b 9f [2] b5 bd [2] a1 a6 [2] ae bc [2] b0 a1 [2] b2 a0 [2] a9 a6 [2] b5 a1 [2] a9 8e }

  condition:
    any of them
}