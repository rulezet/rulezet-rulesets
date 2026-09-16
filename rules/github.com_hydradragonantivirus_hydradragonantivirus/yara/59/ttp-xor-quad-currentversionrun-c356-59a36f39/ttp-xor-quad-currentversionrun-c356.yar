rule TTP_XOR_QUAD_CurrentVersionRun_c356 {
  strings:
    $key_c356 = { 90 39 [2] b4 37 [2] 9f 1b [2] b1 39 [2] a5 22 [2] aa 38 [2] b4 25 [2] b6 24 [2] ad 22 [2] b1 25 [2] ad 0a }

  condition:
    any of them
}