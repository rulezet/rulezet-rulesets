rule TTP_XOR_QUAD_CurrentVersionRun_c3c2 {
  strings:
    $key_c3c2 = { 90 ad [2] b4 a3 [2] 9f 8f [2] b1 ad [2] a5 b6 [2] aa ac [2] b4 b1 [2] b6 b0 [2] ad b6 [2] b1 b1 [2] ad 9e }

  condition:
    any of them
}