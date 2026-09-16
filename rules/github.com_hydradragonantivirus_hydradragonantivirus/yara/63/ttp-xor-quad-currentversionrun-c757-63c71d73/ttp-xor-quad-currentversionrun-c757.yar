rule TTP_XOR_QUAD_CurrentVersionRun_c757 {
  strings:
    $key_c757 = { 94 38 [2] b0 36 [2] 9b 1a [2] b5 38 [2] a1 23 [2] ae 39 [2] b0 24 [2] b2 25 [2] a9 23 [2] b5 24 [2] a9 0b }

  condition:
    any of them
}