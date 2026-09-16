rule TTP_XOR_QUAD_CurrentVersionRun_c343 {
  strings:
    $key_c343 = { 90 2c [2] b4 22 [2] 9f 0e [2] b1 2c [2] a5 37 [2] aa 2d [2] b4 30 [2] b6 31 [2] ad 37 [2] b1 30 [2] ad 1f }

  condition:
    any of them
}