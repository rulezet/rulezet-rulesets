rule TTP_XOR_QUAD_CurrentVersionRun_c323 {
  strings:
    $key_c323 = { 90 4c [2] b4 42 [2] 9f 6e [2] b1 4c [2] a5 57 [2] aa 4d [2] b4 50 [2] b6 51 [2] ad 57 [2] b1 50 [2] ad 7f }

  condition:
    any of them
}