rule TTP_XOR_QUAD_CurrentVersionRun_c372 {
  strings:
    $key_c372 = { 90 1d [2] b4 13 [2] 9f 3f [2] b1 1d [2] a5 06 [2] aa 1c [2] b4 01 [2] b6 00 [2] ad 06 [2] b1 01 [2] ad 2e }

  condition:
    any of them
}