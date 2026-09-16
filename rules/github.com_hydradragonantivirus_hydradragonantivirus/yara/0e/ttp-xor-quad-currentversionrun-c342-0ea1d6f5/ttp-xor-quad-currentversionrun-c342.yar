rule TTP_XOR_QUAD_CurrentVersionRun_c342 {
  strings:
    $key_c342 = { 90 2d [2] b4 23 [2] 9f 0f [2] b1 2d [2] a5 36 [2] aa 2c [2] b4 31 [2] b6 30 [2] ad 36 [2] b1 31 [2] ad 1e }

  condition:
    any of them
}