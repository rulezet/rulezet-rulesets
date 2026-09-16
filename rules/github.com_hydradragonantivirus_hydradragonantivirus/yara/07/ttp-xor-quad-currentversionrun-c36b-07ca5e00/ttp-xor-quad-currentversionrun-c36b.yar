rule TTP_XOR_QUAD_CurrentVersionRun_c36b {
  strings:
    $key_c36b = { 90 04 [2] b4 0a [2] 9f 26 [2] b1 04 [2] a5 1f [2] aa 05 [2] b4 18 [2] b6 19 [2] ad 1f [2] b1 18 [2] ad 37 }

  condition:
    any of them
}