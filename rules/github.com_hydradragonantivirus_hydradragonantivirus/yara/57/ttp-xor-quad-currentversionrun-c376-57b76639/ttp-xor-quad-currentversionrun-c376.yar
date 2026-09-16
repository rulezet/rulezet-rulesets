rule TTP_XOR_QUAD_CurrentVersionRun_c376 {
  strings:
    $key_c376 = { 90 19 [2] b4 17 [2] 9f 3b [2] b1 19 [2] a5 02 [2] aa 18 [2] b4 05 [2] b6 04 [2] ad 02 [2] b1 05 [2] ad 2a }

  condition:
    any of them
}