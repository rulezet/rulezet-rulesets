rule TTP_XOR_QUAD_CurrentVersionRun_c379 {
  strings:
    $key_c379 = { 90 16 [2] b4 18 [2] 9f 34 [2] b1 16 [2] a5 0d [2] aa 17 [2] b4 0a [2] b6 0b [2] ad 0d [2] b1 0a [2] ad 25 }

  condition:
    any of them
}