rule TTP_XOR_QUAD_CurrentVersionRun_d643 {
  strings:
    $key_d643 = { 85 2c [2] a1 22 [2] 8a 0e [2] a4 2c [2] b0 37 [2] bf 2d [2] a1 30 [2] a3 31 [2] b8 37 [2] a4 30 [2] b8 1f }

  condition:
    any of them
}