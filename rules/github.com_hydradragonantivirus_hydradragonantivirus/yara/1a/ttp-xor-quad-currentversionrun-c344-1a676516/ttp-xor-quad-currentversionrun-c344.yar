rule TTP_XOR_QUAD_CurrentVersionRun_c344 {
  strings:
    $key_c344 = { 90 2b [2] b4 25 [2] 9f 09 [2] b1 2b [2] a5 30 [2] aa 2a [2] b4 37 [2] b6 36 [2] ad 30 [2] b1 37 [2] ad 18 }

  condition:
    any of them
}