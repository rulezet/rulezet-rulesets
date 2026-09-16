rule TTP_XOR_QUAD_CurrentVersionRun_c358 {
  strings:
    $key_c358 = { 90 37 [2] b4 39 [2] 9f 15 [2] b1 37 [2] a5 2c [2] aa 36 [2] b4 2b [2] b6 2a [2] ad 2c [2] b1 2b [2] ad 04 }

  condition:
    any of them
}