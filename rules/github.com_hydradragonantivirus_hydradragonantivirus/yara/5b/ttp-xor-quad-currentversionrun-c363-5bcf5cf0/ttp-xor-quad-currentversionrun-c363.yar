rule TTP_XOR_QUAD_CurrentVersionRun_c363 {
  strings:
    $key_c363 = { 90 0c [2] b4 02 [2] 9f 2e [2] b1 0c [2] a5 17 [2] aa 0d [2] b4 10 [2] b6 11 [2] ad 17 [2] b1 10 [2] ad 3f }

  condition:
    any of them
}