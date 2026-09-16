rule TTP_XOR_QUAD_CurrentVersionRun_c375 {
  strings:
    $key_c375 = { 90 1a [2] b4 14 [2] 9f 38 [2] b1 1a [2] a5 01 [2] aa 1b [2] b4 06 [2] b6 07 [2] ad 01 [2] b1 06 [2] ad 29 }

  condition:
    any of them
}