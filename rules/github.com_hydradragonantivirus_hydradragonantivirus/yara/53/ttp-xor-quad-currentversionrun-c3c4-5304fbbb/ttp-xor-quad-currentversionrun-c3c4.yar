rule TTP_XOR_QUAD_CurrentVersionRun_c3c4 {
  strings:
    $key_c3c4 = { 90 ab [2] b4 a5 [2] 9f 89 [2] b1 ab [2] a5 b0 [2] aa aa [2] b4 b7 [2] b6 b6 [2] ad b0 [2] b1 b7 [2] ad 98 }

  condition:
    any of them
}