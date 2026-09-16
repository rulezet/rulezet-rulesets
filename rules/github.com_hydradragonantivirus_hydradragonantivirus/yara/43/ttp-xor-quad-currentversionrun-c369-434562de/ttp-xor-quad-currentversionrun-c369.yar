rule TTP_XOR_QUAD_CurrentVersionRun_c369 {
  strings:
    $key_c369 = { 90 06 [2] b4 08 [2] 9f 24 [2] b1 06 [2] a5 1d [2] aa 07 [2] b4 1a [2] b6 1b [2] ad 1d [2] b1 1a [2] ad 35 }

  condition:
    any of them
}