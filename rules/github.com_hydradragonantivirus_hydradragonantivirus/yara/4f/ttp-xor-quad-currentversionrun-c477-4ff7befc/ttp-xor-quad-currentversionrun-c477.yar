rule TTP_XOR_QUAD_CurrentVersionRun_c477 {
  strings:
    $key_c477 = { 97 18 [2] b3 16 [2] 98 3a [2] b6 18 [2] a2 03 [2] ad 19 [2] b3 04 [2] b1 05 [2] aa 03 [2] b6 04 [2] aa 2b }

  condition:
    any of them
}