rule TTP_XOR_QUAD_CurrentVersionRun_c354 {
  strings:
    $key_c354 = { 90 3b [2] b4 35 [2] 9f 19 [2] b1 3b [2] a5 20 [2] aa 3a [2] b4 27 [2] b6 26 [2] ad 20 [2] b1 27 [2] ad 08 }

  condition:
    any of them
}