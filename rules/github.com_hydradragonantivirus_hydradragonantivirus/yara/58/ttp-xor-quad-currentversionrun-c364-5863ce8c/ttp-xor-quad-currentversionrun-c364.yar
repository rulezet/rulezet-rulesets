rule TTP_XOR_QUAD_CurrentVersionRun_c364 {
  strings:
    $key_c364 = { 90 0b [2] b4 05 [2] 9f 29 [2] b1 0b [2] a5 10 [2] aa 0a [2] b4 17 [2] b6 16 [2] ad 10 [2] b1 17 [2] ad 38 }

  condition:
    any of them
}