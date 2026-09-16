rule TTP_XOR_QUAD_CurrentVersionRun_c346 {
  strings:
    $key_c346 = { 90 29 [2] b4 27 [2] 9f 0b [2] b1 29 [2] a5 32 [2] aa 28 [2] b4 35 [2] b6 34 [2] ad 32 [2] b1 35 [2] ad 1a }

  condition:
    any of them
}