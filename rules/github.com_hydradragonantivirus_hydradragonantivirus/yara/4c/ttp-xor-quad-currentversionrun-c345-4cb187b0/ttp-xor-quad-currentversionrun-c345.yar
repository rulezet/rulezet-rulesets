rule TTP_XOR_QUAD_CurrentVersionRun_c345 {
  strings:
    $key_c345 = { 90 2a [2] b4 24 [2] 9f 08 [2] b1 2a [2] a5 31 [2] aa 2b [2] b4 36 [2] b6 37 [2] ad 31 [2] b1 36 [2] ad 19 }

  condition:
    any of them
}