rule TTP_XOR_QUAD_CurrentVersionRun_c737 {
  strings:
    $key_c737 = { 94 58 [2] b0 56 [2] 9b 7a [2] b5 58 [2] a1 43 [2] ae 59 [2] b0 44 [2] b2 45 [2] a9 43 [2] b5 44 [2] a9 6b }

  condition:
    any of them
}