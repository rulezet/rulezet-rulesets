rule TTP_XOR_QUAD_CurrentVersionRun_c3c6 {
  strings:
    $key_c3c6 = { 90 a9 [2] b4 a7 [2] 9f 8b [2] b1 a9 [2] a5 b2 [2] aa a8 [2] b4 b5 [2] b6 b4 [2] ad b2 [2] b1 b5 [2] ad 9a }

  condition:
    any of them
}