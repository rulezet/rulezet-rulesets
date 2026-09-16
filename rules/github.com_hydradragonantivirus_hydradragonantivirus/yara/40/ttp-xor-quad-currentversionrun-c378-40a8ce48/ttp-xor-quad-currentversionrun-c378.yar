rule TTP_XOR_QUAD_CurrentVersionRun_c378 {
  strings:
    $key_c378 = { 90 17 [2] b4 19 [2] 9f 35 [2] b1 17 [2] a5 0c [2] aa 16 [2] b4 0b [2] b6 0a [2] ad 0c [2] b1 0b [2] ad 24 }

  condition:
    any of them
}